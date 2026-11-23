"""Shared data models: the single Finding schema every agent produces/consumes."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    agent: str                 # "code_analysis" | "security"
    category: str              # machine key, e.g. "sql_injection"
    title: str
    severity: str
    line: int
    snippet: str
    description: str
    cwe: str = ""
    owasp: str = ""
    id: str = ""
    remediation: str = ""
    fixed_code: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def mk(agent, category, title, severity, line, lines, description, cwe="", owasp="") -> Finding:
    snippet = lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""
    return Finding(agent, category, title, severity, line, snippet, description, cwe, owasp)


@dataclass
class Submission:
    code: str
    language: str              # "python" | "java"
    filename: str
    valid: bool = True
    errors: List[str] = field(default_factory=list)

    @property
    def lines(self) -> List[str]:
        return self.code.splitlines()


@dataclass
class Review:
    submission: Submission
    findings: List[Finding]
    health_score: int
    grade: str
    summary: Dict[str, Any]
    timings: Dict[str, float]
    used_llm: bool
