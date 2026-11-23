"""Milestone 3 - RAG Conversational Code Assistant, grounded in the secure-coding KB + the current review."""
import re
from typing import List, Tuple


class Assistant:
    def __init__(self, kb, llm=None):
        self.kb, self.llm = kb, llm

    def _match_findings(self, q: str, findings):
        hits = []
        for m in re.finditer(r"\bline\s*(\d+)", q, re.I):
            hits += [f for f in findings if f.line == int(m.group(1))]
        for m in re.finditer(r"\bF-?(\d+)\b", q, re.I):
            hits += [f for f in findings if f.id.upper() == f"F-{int(m.group(1)):03d}"]
        if not hits:
            words = set(re.findall(r"[a-z]{4,}", q.lower()))
            for f in findings:
                keys = set(f.category.split("_")) | set(re.findall(r"[a-z]{4,}", f.title.lower()))
                if words & keys - {"with", "that", "this", "used", "from"}:
                    hits.append(f)
        seen, out = set(), []
        for f in hits:
            if f.id not in seen:
                seen.add(f.id); out.append(f)
        return out[:3]

    def ask(self, question: str, findings: list, history: List[Tuple[str, str]] = ()) -> dict:
        matched = self._match_findings(question, findings)
        query = question + " " + " ".join(f"{f.title} {f.cwe}" for f in matched)
        hits = self.kb.search(query, k=3)
        sources = sorted({c.source for c, _ in hits})
        if not hits and not matched:
            return {"answer": "I couldn't find that in the secure-coding knowledge base. Try asking about a finding "
                              "(e.g. 'explain line 12' or 'how do I fix SQL injection?').", "sources": []}
        if self.llm is not None and self.llm.available:
            try:
                ctx = "\n\n".join(f"[{c.source}] {c.text}" for c, _ in hits)
                fctx = "\n".join(f"{f.id} line {f.line}: {f.title} | fix: {f.remediation}" for f in matched)
                hist = "\n".join(f"{r}: {t}" for r, t in list(history)[-6:])
                ans = self.llm.complete(
                    "You are a secure-coding assistant. Answer ONLY from the provided knowledge-base context and review "
                    "findings. If the context is insufficient, say so. Be concise and cite source file names.",
                    f"Context:\n{ctx}\n\nFindings:\n{fctx}\n\nHistory:\n{hist}\n\nQuestion: {question}", max_tokens=700)
                return {"answer": ans.strip(), "sources": sources}
            except Exception:
                pass
        parts = []
        for f in matched:
            parts.append(f"**{f.id} - {f.title}** (line {f.line}, {f.severity})\n\n{f.description}\n\n"
                         f"**Fix:** {f.remediation}" + (f"\n\n```\n{f.fixed_code}\n```" if f.fixed_code else ""))
        if hits:
            parts.append("**From the knowledge base** (" + hits[0][0].heading + "):\n\n" + hits[0][0].text)
        return {"answer": "\n\n---\n\n".join(parts), "sources": sources}
