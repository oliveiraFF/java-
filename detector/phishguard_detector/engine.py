"""检测引擎统一入口：解析 → 规则 → 模型 → 融合。

api（手动检测）和 worker（自动检测）都只调用 Engine.detect_bytes / detect_parsed。
模型是可选的：模型文件不存在时只用规则，系统仍可运行。
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from phishguard_detector.fusion import FusionConfig, Verdict, fuse
from phishguard_detector.parser import ParsedEmail, parse_bytes
from phishguard_detector.rules import RuleResult, evaluate


class TextModel(Protocol):
    name: str

    def predict_proba(self, texts: list[str]) -> list[float]: ...


class BaselineModel:
    """TF-IDF 基线（joblib 文件，由 ml/scripts/train_baseline.py 产出）。"""

    name = "baseline"

    def __init__(self, path: str | Path, calibrated: bool = False):
        """calibrated=True 时，把训练时在验证集上选出的阈值（误报率 ≤ 1%）映射到 0.5。

        加入大量正常邮件训练后，模型整体打分偏低，固定 0.5 不再合适（实验 7）。
        映射是单调分段线性的：只移动判定点，不改变邮件之间的排序，
        这样融合公式和 50 / 80 的判定线都不用改。实验脚本使用原始分数（calibrated=False）。
        """
        import joblib  # 延迟导入：只有加载模型时才需要 scikit-learn
        import numpy as np

        self._np = np
        bundle = joblib.load(path)
        self.vec, self.model = bundle["vectorizer"], bundle["model"]
        self.anchor: float | None = None
        if calibrated and bundle.get("threshold_fpr1") is not None:
            t = float(bundle["threshold_fpr1"])
            self.anchor = t if hasattr(self.model, "predict_proba") else float(1.0 / (1.0 + np.exp(-2.0 * t)))

    def _raw(self, X):
        if hasattr(self.model, "predict_proba"):
            return self.model.predict_proba(X)[:, 1]
        # 线性 SVM 没有概率输出：把间隔用 sigmoid 映射到 0–1（阈值 0 对应 0.5）
        return 1.0 / (1.0 + self._np.exp(-2.0 * self.model.decision_function(X)))

    def predict_proba(self, texts: list[str]) -> list[float]:
        p = self._raw(self.vec.transform(texts))
        t = self.anchor
        if t is not None and 0.0 < t < 1.0:
            p = self._np.where(p < t, 0.5 * p / t, 0.5 + 0.5 * (p - t) / (1.0 - t))
        return p.tolist()


@dataclass
class Detection:
    parsed: ParsedEmail
    rules: RuleResult
    verdict: Verdict
    latency_ms: float

    def to_dict(self) -> dict:
        p = self.parsed
        return {
            "verdict": self.verdict.to_dict(),
            "rules": self.rules.to_dict(),
            "email": {
                "subject": p.subject, "from_addr": p.from_addr, "from_name": p.from_name, "reply_to": p.reply_to,
                "auth_results": p.auth_results, "urls": [u.__dict__ for u in p.urls],
                "attachments": [a.__dict__ for a in p.attachments], "text_excerpt": p.text[:4000],
            },
            "latency_ms": round(self.latency_ms, 1),
        }


class Engine:
    def __init__(self, models: list[TextModel] | None = None, cfg: FusionConfig | None = None):
        self.models = models or []
        self.cfg = cfg or FusionConfig()

    @classmethod
    def from_model_dir(cls, model_dir: str | Path, cfg: FusionConfig | None = None) -> Engine:
        """优先加载"钓鱼 vs 非钓鱼"模型（baseline_tfidf_phish.joblib）。

        按原始标签训练的 baseline_tfidf.joblib 会把营销、通知类邮件当成垃圾邮件，
        在真实邮箱上误报率很高（见 docs/实验记录.md 实验 5），只在没有新模型时作为后备。
        """
        models: list[TextModel] = []
        # 优先级：中英混合 + 通知类正常邮件（实验 7）> 中英混合（实验 6）> 英文"钓鱼 vs 非钓鱼"（实验 5）> 原始标签
        # "钓鱼 vs 非钓鱼"模型启用验证集阈值校准；原始标签模型保持原样
        for name, calib in (("baseline_tfidf_phish_mixed2.joblib", True), ("baseline_tfidf_phish_mixed.joblib", True),
                            ("baseline_tfidf_phish.joblib", True), ("baseline_tfidf.joblib", False)):
            path = Path(model_dir) / name
            if path.exists():
                models.append(BaselineModel(path, calibrated=calib))
                break
        return cls(models, cfg)

    def detect_bytes(self, raw: bytes, *, allowlisted: bool = False) -> Detection:
        return self.detect_parsed(parse_bytes(raw), allowlisted=allowlisted)

    def detect_parsed(self, pe: ParsedEmail, *, allowlisted: bool = False) -> Detection:
        t = time.perf_counter()
        rules = evaluate(pe)
        text = pe.model_input()
        scores = {m.name: float(m.predict_proba([text])[0]) for m in self.models} if text else {}
        auth_failed = any(pe.auth_results.get(k) == "fail" for k in ("spf", "dkim", "dmarc"))
        verdict = fuse(rules, scores, allowlisted=allowlisted, auth_failed=auth_failed, cfg=self.cfg)
        return Detection(pe, rules, verdict, (time.perf_counter() - t) * 1000)
