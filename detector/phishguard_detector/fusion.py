"""融合打分：规则分 + 模型概率 → 风险分（0–100）与判定。

公式（开发文档 7.5）：
    S = 100 × (w_r · R/100 + w_m · P)，P 为可用模型概率中的最大值
    命中关键规则 → S = max(S, 90)
    命中白名单且身份认证未失败 → S -= 20
判定：S ≥ 80 钓鱼；50 ≤ S < 80 可疑；否则安全。
权重与阈值后续在验证集上网格搜索确定，这里是默认值。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from phishguard_detector.rules import RuleResult

VERDICT_ZH = {"phishing": "钓鱼", "suspicious": "可疑", "safe": "安全"}


@dataclass
class FusionConfig:
    w_rules: float = 0.4
    w_model: float = 0.6
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


def fuse(rules: RuleResult, model_scores: dict[str, float], *, allowlisted: bool = False,
         auth_failed: bool = False, cfg: FusionConfig | None = None) -> Verdict:
    cfg = cfg or FusionConfig()
    p = max(model_scores.values()) if model_scores else None
    if p is None:
        # 没有可用模型时只靠规则：规则分直接作为风险分
        s = float(rules.score)
    else:
        s = 100.0 * (cfg.w_rules * rules.score / 100.0 + cfg.w_model * p)
        # 模型非常确信时，不让"规则未命中"把分数拉得过低
        s = max(s, 100.0 * p * 0.85) if p >= 0.95 else s
    if rules.critical:
        s = max(s, cfg.critical_floor)
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
