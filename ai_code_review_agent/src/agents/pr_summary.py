"""Milestone 3 - PR Summary Agent: executive overview, severity breakdown, prioritized fix list."""
from typing import List, Dict
from ..models import Finding, SEV_RANK
from ..scoring import severity_counts, health_score, grade


def run(sub, findings: List[Finding], llm=None) -> Dict:
    counts = severity_counts(findings)
    score = health_score(findings)
    g = grade(score)
    ranked = sorted(findings, key=lambda f: (SEV_RANK[f.severity], f.line))
    sec = [f for f in findings if f.agent == "security"]
    q = [f for f in findings if f.agent == "code_analysis"]
    verdict = ("Do not merge - critical security issues must be fixed first." if counts["Critical"]
               else "Changes requested - high-severity issues found." if counts["High"]
               else "Approve with comments - minor issues only." if findings else "Approve - no issues detected.")
    overview = (f"Reviewed `{sub.filename}` ({sub.language.title()}, {len(sub.lines)} lines). "
                f"Found {len(findings)} issue(s): {len(sec)} security and {len(q)} code-quality. "
                f"Code health score {score}/100 (grade {g}). {verdict}")
    if llm is not None and llm.available and findings:
        try:
            top = "\n".join(f"- [{f.severity}] {f.title} (line {f.line})" for f in ranked[:8])
            overview = llm.complete(
                "You write concise pull-request review summaries for engineers.",
                f"Write a 3-4 sentence executive overview. Stats: {counts}, score {score}/100, verdict: {verdict}\nTop findings:\n{top}",
                max_tokens=300).strip()
        except Exception:
            pass
    priority = [{"rank": i + 1, "id": f.id, "severity": f.severity, "title": f.title, "line": f.line,
                 "action": f.remediation.split(". ")[0].strip(".") + "."} for i, f in enumerate(ranked[:10])]
    md = [f"## PR Review: {sub.filename}", "", overview, "", "### Severity breakdown"]
    md += [f"- **{s}**: {n}" for s, n in counts.items()]
    md += ["", "### Prioritized fix list"] + [f"{p['rank']}. **[{p['severity']}]** {p['title']} (line {p['line']})" for p in priority]
    return {"overview": overview, "verdict": verdict, "counts": counts, "score": score, "grade": g,
            "priority": priority, "markdown": "\n".join(md)}
