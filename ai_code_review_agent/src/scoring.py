"""Severity counting and overall code-health scoring."""
from typing import List, Dict
from .models import Finding, SEVERITIES

DEDUCTION = {"Critical": 15, "High": 8, "Medium": 4, "Low": 1.5, "Info": 0.25}


def severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    return counts


def health_score(findings: List[Finding]) -> int:
    return max(0, round(100 - sum(DEDUCTION[f.severity] for f in findings)))


def grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
