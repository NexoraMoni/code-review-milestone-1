"""Milestone 1 - Code Submission Module: paste/upload + syntax validation (Python & Java)."""
import ast
import re
from typing import Optional
from . import config
from .models import Submission

_BLANK = lambda m: re.sub(r"[^\n]", " ", m.group())
_JAVA_NOISE = re.compile(r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])'", re.S)


def java_sanitize(code: str) -> str:
    """Blank out comments/strings/chars but keep line structure intact."""
    return _JAVA_NOISE.sub(_BLANK, code)


def detect_language(code: str, filename: Optional[str] = None) -> str:
    if filename:
        if filename.lower().endswith(".py"):
            return "python"
        if filename.lower().endswith(".java"):
            return "java"
    java_hits = len(re.findall(r"\b(public|private)\s+(static\s+)?(class|void|int|String)\b|import\s+java\.|;\s*$", code, re.M))
    py_hits = len(re.findall(r"^\s*(def |import \w+|from \w+ import|class \w+.*:)", code, re.M))
    return "java" if java_hits > py_hits else "python"


def _validate_python(code: str):
    try:
        ast.parse(code)
        return []
    except SyntaxError as e:
        return [f"Python syntax error at line {e.lineno}: {e.msg}"]


def _validate_java(code: str):
    errors = []
    if code.count("/*") > code.count("*/"):
        errors.append("Unterminated block comment.")
    clean = java_sanitize(code)
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    for ln, line in enumerate(clean.splitlines(), 1):
        for ch in line:
            if ch in "([{":
                stack.append((ch, ln))
            elif ch in pairs:
                if not stack or stack[-1][0] != pairs[ch]:
                    errors.append(f"Unbalanced '{ch}' at line {ln}.")
                    return errors
                stack.pop()
    if stack:
        errors.append(f"Unclosed '{stack[-1][0]}' opened at line {stack[-1][1]}.")
    if not re.search(r"\b(class|interface|enum|record)\s+\w+", clean):
        errors.append("No class/interface/enum declaration found - is this a Java source file?")
    return errors


def build_submission(code: str, filename: Optional[str] = None, language: Optional[str] = None) -> Submission:
    code = code.replace("\r\n", "\n")
    filename = filename or "pasted_code"
    if not code.strip():
        return Submission(code, language or "python", filename, False, ["No code submitted."])
    if len(code.encode()) > config.MAX_CODE_BYTES:
        return Submission(code, language or "python", filename, False,
                          [f"File too large (limit {config.MAX_CODE_BYTES // 1000} KB)."])
    lang = (language or detect_language(code, filename)).lower()
    if lang not in ("python", "java"):
        return Submission(code, lang, filename, False, ["Only Python and Java are supported."])
    errors = _validate_python(code) if lang == "python" else _validate_java(code)
    return Submission(code, lang, filename, not errors, errors)


def read_upload(file_bytes: bytes, filename: str) -> Submission:
    if not filename.lower().endswith((".py", ".java")):
        return Submission("", "python", filename, False, ["Upload a .py or .java file."])
    try:
        code = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return Submission("", "python", filename, False, ["File is not valid UTF-8 text."])
    return build_submission(code, filename)
