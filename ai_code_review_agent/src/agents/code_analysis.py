"""Milestone 2 - Code Analysis Agent: smells, complexity, anti-patterns (Python AST + Java static scan)."""
import ast
import re
from typing import List
from .. import config as C
from ..models import Finding, mk
from ..submission import java_sanitize

A = "code_analysis"


# ------------------------------------------------------------------ Python
def _complexity(node) -> int:
    n = 1
    for sub in ast.walk(node):
        if isinstance(sub, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp,
                            ast.comprehension, ast.Assert)):
            n += 1
        elif isinstance(sub, ast.BoolOp):
            n += len(sub.values) - 1
    return n


def _depth(node, d=0) -> int:
    best = d
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)):
            best = max(best, _depth(child, d + 1))
        else:
            best = max(best, _depth(child, d))
    return best


def _analyze_python(code: str, lines: List[str]) -> List[Finding]:
    out: List[Finding] = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return out
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name, ln = node.name, node.lineno
            length = (node.end_lineno or ln) - ln + 1
            if length > C.MAX_FUNC_LINES:
                out.append(mk(A, "long_function", f"Long function '{name}' ({length} lines)",
                              "High" if length > 100 else "Medium", ln, lines,
                              f"Function spans {length} lines (limit {C.MAX_FUNC_LINES}); likely has multiple responsibilities."))
            cc = _complexity(node)
            if cc > C.MAX_COMPLEXITY:
                out.append(mk(A, "high_complexity", f"High cyclomatic complexity in '{name}' ({cc})",
                              "High" if cc > 20 else "Medium", ln, lines,
                              f"Cyclomatic complexity {cc} exceeds {C.MAX_COMPLEXITY}; hard to test and maintain."))
            dp = _depth(node)
            if dp > C.MAX_NESTING:
                out.append(mk(A, "deep_nesting", f"Deep nesting in '{name}' ({dp} levels)", "Medium", ln, lines,
                              f"Control-flow nesting of {dp} levels exceeds {C.MAX_NESTING}."))
            a = node.args
            params = [p.arg for p in a.posonlyargs + a.args + a.kwonlyargs if p.arg not in ("self", "cls")]
            if len(params) > C.MAX_PARAMS:
                out.append(mk(A, "many_params", f"Too many parameters in '{name}' ({len(params)})", "Low", ln, lines,
                              f"{len(params)} parameters (limit {C.MAX_PARAMS}); consider a parameter object."))
            for d in a.defaults + [x for x in a.kw_defaults if x is not None]:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                    out.append(mk(A, "mutable_default", f"Mutable default argument in '{name}'", "Medium", ln, lines,
                                  "Mutable default values are shared across calls and cause subtle bugs."))
                    break
            if not ast.get_docstring(node) and not name.startswith("_") and length > 5:
                out.append(mk(A, "missing_docstring", f"Missing docstring: '{name}'", "Info", ln, lines,
                              "Public function lacks a docstring."))
        elif isinstance(node, ast.ClassDef):
            methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if len(methods) > C.MAX_CLASS_METHODS:
                out.append(mk(A, "god_class", f"Large class '{node.name}' ({len(methods)} methods)", "Medium",
                              node.lineno, lines, "Class has too many responsibilities (god class)."))
        elif isinstance(node, ast.ExceptHandler):
            if node.type is None:
                out.append(mk(A, "bare_except", "Bare 'except:' clause", "Medium", node.lineno, lines,
                              "Catches every exception including KeyboardInterrupt/SystemExit and hides bugs."))
            elif isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException") \
                    and all(isinstance(s, ast.Pass) for s in node.body):
                out.append(mk(A, "empty_catch", "Exception swallowed silently", "Medium", node.lineno, lines,
                              "Broad exception caught and ignored."))
        elif isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
            out.append(mk(A, "wildcard_import", f"Wildcard import from '{node.module}'", "Low", node.lineno, lines,
                          "Wildcard imports pollute the namespace and hide dependencies."))
        elif isinstance(node, ast.Global):
            out.append(mk(A, "global_state", "Use of 'global' state", "Low", node.lineno, lines,
                          "Mutable global state makes code harder to reason about and test."))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
            out.append(mk(A, "print_statement", "print() used instead of logging", "Info", node.lineno, lines,
                          "Use the logging module for diagnostics."))
    return out


# -------------------------------------------------------------------- Java
_METHOD = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*[\w<>\[\],.? ]+?\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w\s,.]+)?\{")
_SKIP = {"if", "for", "while", "switch", "catch", "synchronized", "else", "try"}


def _analyze_java(code: str, lines: List[str]) -> List[Finding]:
    out: List[Finding] = []
    clean = java_sanitize(code)
    cl = clean.splitlines()
    n_methods = 0
    for i, line in enumerate(cl):
        m = _METHOD.match(line)
        if not m or m.group(1) in _SKIP or re.match(r"\s*(new|return|else|throw)\b", line):
            continue
        n_methods += 1
        name, params = m.group(1), m.group(2).strip()
        depth, end, max_depth = 0, i, 0
        for j in range(i, len(cl)):
            for ch in cl[j]:
                if ch == "{":
                    depth += 1
                    max_depth = max(max_depth, depth)
                elif ch == "}":
                    depth -= 1
            if depth == 0:
                end = j
                break
        body = "\n".join(cl[i:end + 1])
        length = end - i + 1
        cc = 1 + len(re.findall(r"\b(if|for|while|case|catch)\b|&&|\|\||\?(?!\?)", body))
        ln = i + 1
        if length > C.MAX_FUNC_LINES:
            out.append(mk(A, "long_function", f"Long method '{name}' ({length} lines)",
                          "High" if length > 100 else "Medium", ln, lines,
                          f"Method spans {length} lines (limit {C.MAX_FUNC_LINES})."))
        if cc > C.MAX_COMPLEXITY:
            out.append(mk(A, "high_complexity", f"High cyclomatic complexity in '{name}' ({cc})",
                          "High" if cc > 20 else "Medium", ln, lines,
                          f"Cyclomatic complexity {cc} exceeds {C.MAX_COMPLEXITY}."))
        if max_depth - 1 > C.MAX_NESTING:
            out.append(mk(A, "deep_nesting", f"Deep nesting in '{name}' ({max_depth - 1} levels)", "Medium", ln, lines,
                          f"Block nesting of {max_depth - 1} levels exceeds {C.MAX_NESTING}."))
        n_params = len([p for p in params.split(",") if p.strip()]) if params else 0
        if n_params > C.MAX_PARAMS:
            out.append(mk(A, "many_params", f"Too many parameters in '{name}' ({n_params})", "Low", ln, lines,
                          f"{n_params} parameters (limit {C.MAX_PARAMS})."))
    if n_methods > C.MAX_CLASS_METHODS:
        out.append(mk(A, "god_class", f"Large class ({n_methods} methods)", "Medium", 1, lines,
                      "File declares too many methods; split responsibilities."))
    for m in re.finditer(r"catch\s*\([^)]*\)\s*\{\s*\}", clean):
        out.append(mk(A, "empty_catch", "Empty catch block", "Medium", clean[:m.start()].count("\n") + 1, lines,
                      "Exception is swallowed silently."))
    for i, line in enumerate(cl, 1):
        if re.search(r"catch\s*\(\s*(final\s+)?(Exception|Throwable)\b", line):
            out.append(mk(A, "generic_catch", "Catching generic Exception/Throwable", "Low", i, lines,
                          "Catch specific exception types."))
        if "System.out.print" in line or "System.err.print" in line:
            out.append(mk(A, "print_statement", "System.out used instead of a logger", "Info", i, lines,
                          "Use a logging framework (SLF4J)."))
        if ".printStackTrace(" in line:
            out.append(mk(A, "print_statement", "printStackTrace() used", "Low", i, lines,
                          "Stack traces should be logged, not printed."))
        if re.match(r"\s*public\s+(?!static|final|class|interface|enum|abstract|record)[\w<>\[\],]+\s+\w+\s*(=|;)", line):
            out.append(mk(A, "public_field", "Public mutable field", "Low", i, lines,
                          "Expose state through accessors to preserve encapsulation."))
        if re.match(r"\s*import\s+[\w.]+\*\s*;", line) or re.match(r"\s*import\s+[\w.]+\.\*\s*;", line):
            out.append(mk(A, "wildcard_import", "Wildcard import", "Low", i, lines,
                          "Import only what is needed."))
    return out


# ------------------------------------------------------------------ common
def _common(lines: List[str], lang: str) -> List[Finding]:
    out = []
    long_lines = [i for i, l in enumerate(lines, 1) if len(l) > C.MAX_LINE_LEN]
    if long_lines:
        out.append(mk(A, "long_lines", f"{len(long_lines)} line(s) exceed {C.MAX_LINE_LEN} chars", "Info",
                      long_lines[0], lines, "Overlong lines reduce readability."))
    marker = "#" if lang == "python" else "//"
    for i, l in enumerate(lines, 1):
        if re.search(re.escape(marker) + r".*\b(TODO|FIXME|HACK|XXX)\b", l):
            out.append(mk(A, "todo", "Unresolved TODO/FIXME marker", "Info", i, lines,
                          "Track or resolve outstanding work items."))
    return out


def run(sub) -> List[Finding]:
    lines = sub.lines
    found = _analyze_python(sub.code, lines) if sub.language == "python" else _analyze_java(sub.code, lines)
    return found + _common(lines, sub.language)
