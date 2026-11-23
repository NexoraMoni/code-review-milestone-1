import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pytest
from src import config
from src.rag import KnowledgeBase
from src.submission import build_submission
from src.orchestrator import run_pipeline
from src.agents.assistant import Assistant
from src.report import build_pdf


@pytest.fixture(scope="module")
def kb():
    return KnowledgeBase()


def review(kb, name):
    p = config.SAMPLES_DIR / name
    return run_pipeline(build_submission(p.read_text(), name), kb)


def cats(r):
    return {f.category for f in r.findings}


def test_submission_validation():
    assert not build_submission("def f(:\n  pass", "x.py").valid
    assert not build_submission("class A { void f() { }", "A.java").valid
    assert build_submission("def f():\n    return 1\n", "x.py").valid
    assert not build_submission("", "x.py").valid


def test_rag_retrieval(kb):
    top = kb.search("how to prevent sql injection with prepared statements", k=1)[0][0]
    assert "sql_injection" in top.source


def test_clean_sample_is_healthy(kb):
    r = review(kb, "simple_utils.py")
    assert not [f for f in r.findings if f.agent == "security"]
    assert r.health_score >= 90


def test_flask_sample_security(kb):
    c = cats(review(kb, "flask_app_vulnerable.py"))
    for k in ["sql_injection", "hardcoded_secret", "xss", "command_injection", "insecure_deserialization",
              "weak_crypto", "insecure_config", "broken_access_control", "insecure_auth", "bare_except"]:
        assert k in c, k


def test_order_processor_quality(kb):
    c = cats(review(kb, "order_processor.py"))
    for k in ["high_complexity", "deep_nesting", "many_params", "mutable_default", "wildcard_import", "global_state"]:
        assert k in c, k


def test_java_sample(kb):
    r = review(kb, "UserService.java")
    c = cats(r)
    for k in ["sql_injection", "hardcoded_secret", "weak_crypto", "insecure_random", "command_injection",
              "insecure_deserialization", "xss", "broken_access_control", "empty_catch", "public_field",
              "many_params", "deep_nesting", "insecure_config"]:
        assert k in c, k
    assert r.health_score < 50


def test_remediation_and_report(kb):
    r = review(kb, "flask_app_vulnerable.py")
    assert all(f.remediation for f in r.findings)
    assert any(f.fixed_code for f in r.findings if f.category == "sql_injection")
    assert build_pdf(r)[:4] == b"%PDF"


def test_assistant_grounded(kb):
    r = review(kb, "flask_app_vulnerable.py")
    out = Assistant(kb).ask("How do I fix SQL injection on line 18?", r.findings)
    assert "parameter" in out["answer"].lower() and out["sources"]
