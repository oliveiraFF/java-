from phishguard_detector import parse_text
from phishguard_detector.engine import Engine
from phishguard_detector.fusion import fuse
from phishguard_detector.rules import RuleHit, RuleResult


def rr(score=0, critical=False, names=()):
    hits = [RuleHit(f"R{i}", n, "content", 10, "证据", critical) for i, n in enumerate(names)]
    return RuleResult(score, critical, hits)


def test_rules_only_when_no_model():
    v = fuse(rr(60, names=["制造紧迫感"]), {})
    assert v.risk_score == 60 and v.verdict == "suspicious"


def test_model_and_rules_combined_noisy_or():
    v = fuse(rr(50), {"baseline": 0.6})
    assert v.risk_score == round(100 * (1 - 0.4 * (1 - 0.45)))  # 78
    assert v.verdict == "suspicious"


def test_no_rule_hit_equals_model_probability():
    # 规则未命中时，风险分就是模型概率，不会被打折扣
    assert fuse(rr(0), {"baseline": 0.7}).risk_score == 70
    v = fuse(rr(0), {"baseline": 0.99})
    assert v.verdict == "phishing" and "语义" in v.summary


def test_rules_only_raise_risk():
    for p in (0.1, 0.5, 0.9):
        assert fuse(rr(30), {"m": p}).risk_score >= fuse(rr(0), {"m": p}).risk_score


def test_critical_rule_floor():
    v = fuse(rr(40, critical=True, names=["身份认证失败且冒充品牌"]), {"baseline": 0.1})
    assert v.risk_score >= 90 and v.verdict == "phishing"


def test_allowlist_discount_but_not_when_auth_failed():
    assert fuse(rr(60), {}, allowlisted=True).risk_score == 40
    assert fuse(rr(60), {}, allowlisted=True, auth_failed=True).risk_score == 60


def test_baseline_calibration_moves_threshold_keeps_order(tmp_path):
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.svm import LinearSVC

    from phishguard_detector.engine import BaselineModel

    texts = ["verify your account now", "lunch tomorrow", "urgent password reset", "meeting notes attached"] * 5
    y = [1, 0, 1, 0] * 5
    vec = TfidfVectorizer().fit(texts)
    clf = LinearSVC().fit(vec.transform(texts), y)
    p = tmp_path / "m.joblib"
    joblib.dump({"vectorizer": vec, "model": clf, "threshold_fpr1": -0.3}, p)
    raw = BaselineModel(p).predict_proba(texts[:4])
    cal = BaselineModel(p, calibrated=True).predict_proba(texts[:4])
    anchor = 1 / (1 + __import__("math").exp(0.6))
    assert sorted(range(4), key=raw.__getitem__) == sorted(range(4), key=cal.__getitem__)  # 排序不变
    assert all((r >= anchor) == (c >= 0.5) for r, c in zip(raw, cal))  # 验证集阈值对应 0.5


def test_engine_rules_only():
    eng = Engine()
    d = eng.detect_parsed(parse_text("Account suspended", "Please verify your account immediately at http://198.51.100.9/login"))
    assert d.verdict.rule_score > 0
    assert d.to_dict()["verdict"]["verdict"] in ("safe", "suspicious", "phishing")
