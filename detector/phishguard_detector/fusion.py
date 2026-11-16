"""融合打分：规则分 + 模型概率 → 风险分（0–100）与判定。

公式（noisy-OR，把规则和模型视为两条相互独立的证据）：
    r = rule_confidence × R/100            规则分折算为规则层的置信度
    S = 100 × (1 − (1 − P) × (1 − r))      P 为可用模型概率中的最大值
    命中关键规则 → S = max(S, 90)
    命中白名单且身份认证未失败 → S -= 20
判定：S ≥ 80 钓鱼；50 ≤ S < 80 可疑；否则安全。

最初按开发文档使用加权平均 S = 100 × (0.4·R/100 + 0.6·P)。实验 4 发现：
规则未命中时，模型 70% 的把握只能得到 42 分，永远到不了"可疑"阈值，
等于把模型自己的判断打了折扣。noisy-OR 在规则未命中时 S 就等于模型概率，
规则命中只会增加风险，不会降低。详见 docs/实验记录.md 实验 4。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from phishguard_detector.rules import RuleResult

VERDICT_ZH = {"phishing": "钓鱼", "suspicious": "可疑", "safe": "安全"}


@dataclass
class FusionConfig:
    rule_confidence: float = 0.9  # 规则分 100 时规则层的置信度
    phishing_threshold: int = 80
    suspicious_threshold: int = 50
    critical_floor: int = 90
    allowlist_discount: int = 20


@dataclass
class Verdict:
    risk_score: int
    verdict: str  # phishing / suspicious / safe
    rule_score: int
    model_scores: dict[str, float] = field(default_factory=dict)
    allowlisted: bool = False
    summary: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def combine(rule_score: int, p: float | None, *, critical: bool = False, cfg: FusionConfig | None = None) -> float:
    """规则分与模型概率的连续融合结果（0–1），不取整。

    实验评估直接使用这个连续值：DistilBERT 的概率高度饱和（大量 0.001、0.999），
    若先取整到 0–100，正常邮件之间的细微排序会全部丢失。
    """
    cfg = cfg or FusionConfig()
    if p is None:
        s = rule_score / 100.0  # 没有可用模型时只靠规则
    else:
        r = cfg.rule_confidence * rule_score / 100.0
        s = 1.0 - (1.0 - p) * (1.0 - r)
    if critical:
        s = max(s, cfg.critical_floor / 100.0)
    return min(1.0, max(0.0, s))


def fuse(rules: RuleResult, model_scores: dict[str, float], *, allowlisted: bool = False,
         auth_failed: bool = False, cfg: FusionConfig | None = None) -> Verdict:
    cfg = cfg or FusionConfig()
    p = max(model_scores.values()) if model_scores else None
    s = 100.0 * combine(rules.score, p, critical=rules.critical, cfg=cfg)
    if allowlisted and not auth_failed:
        s -= cfg.allowlist_discount
    score = int(round(min(100.0, max(0.0, s))))

    if score >= cfg.phishing_threshold:
        verdict = "phishing"
    elif score >= cfg.suspicious_threshold:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return Verdict(score, verdict, rules.score, dict(model_scores), allowlisted, _summary(verdict, rules, p))


def _summary(verdict: str, rules: RuleResult, p: float | None) -> str:
    top = [h.name for h in rules.hits[:3]]
    if verdict == "safe":
        return "未发现明显的钓鱼特征。" if not top else f"发现少量可疑特征（{'、'.join(top)}），整体风险较低。"
    reasons = "、".join(top) if top else "邮件内容的语义与已知钓鱼邮件高度相似"
    if top and p is not None and p >= 0.8:
        reasons += "，且邮件内容的语义与钓鱼邮件高度相似"
    return f"判定为{VERDICT_ZH[verdict]}邮件：{reasons}。"
