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


def test_model_and_rules_combined():
    v = fuse(rr(50), {"baseline": 0.9})
    assert v.risk_score == round(100 * (0.4 * 0.5 + 0.6 * 0.9))  # 74
    assert v.verdict == "suspicious"


def test_confident_model_not_dragged_down_by_missing_rules():
    v = fuse(rr(0), {"baseline": 0.99})
    assert v.verdict == "phishing"
    assert "语义" in v.summary


def test_critical_rule_floor():
    v = fuse(rr(40, critical=True, names=["身份认证失败且冒充品牌"]), {"baseline": 0.1})
    assert v.risk_score >= 90 and v.verdict == "phishing"


def test_allowlist_discount_but_not_when_auth_failed():
    assert fuse(rr(60), {}, allowlisted=True).risk_score == 40
    assert fuse(rr(60), {}, allowlisted=True, auth_failed=True).risk_score == 60


def test_engine_rules_only():
    eng = Engine()
    d = eng.detect_parsed(parse_text("Account suspended", "Please verify your account immediately at http://198.51.100.9/login"))
    assert d.verdict.rule_score > 0
    assert d.to_dict()["verdict"]["verdict"] in ("safe", "suspicious", "phishing")
