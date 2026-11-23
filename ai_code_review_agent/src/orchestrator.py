"""Milestone 2/3 - Multi-agent orchestration: parallel detection -> merge -> remediation -> PR summary."""
import time
from concurrent.futures import ThreadPoolExecutor
from .agents import code_analysis, security, remediation, pr_summary
from .models import Review, SEV_RANK
from .scoring import health_score, grade


def run_pipeline(sub, kb, llm=None) -> Review:
    if not sub.valid:
        raise ValueError("; ".join(sub.errors))
    t = {}
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=2) as ex:                      # parallel detection agents
        fa, fs = ex.submit(code_analysis.run, sub), ex.submit(security.run, sub)
        findings = fs.result() + fa.result()
    t["detection"] = time.time() - t0

    findings.sort(key=lambda f: (SEV_RANK[f.severity], f.line))        # merged, ordered, unique IDs
    for i, f in enumerate(findings, 1):
        f.id = f"F-{i:03d}"

    t1 = time.time()
    remediation.run(findings, sub.language, kb, llm)
    t["remediation"] = time.time() - t1

    t2 = time.time()
    summary = pr_summary.run(sub, findings, llm)
    t["summary"] = time.time() - t2
    score = health_score(findings)
    return Review(sub, findings, score, grade(score), summary, t, bool(llm and llm.available))
