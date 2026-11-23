"""Milestone 2 - Security Vulnerability Agent: OWASP-oriented scanning with line-level flagging."""
import re
from typing import List
from ..models import Finding, mk

A = "security"

_SQL_KW = r"(select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)"
_SECRET_NAME = r"(password|passwd|pwd|secret|api[_-]?key|apikey|token|private[_-]?key|access[_-]?key)"

# Each rule: category, title, severity, cwe, owasp, description, pattern(s)
RULES = [
    dict(cat="sql_injection", title="SQL injection: query built from string concatenation/formatting", sev="Critical",
         cwe="CWE-89", owasp="A03:2021 Injection",
         desc="User-controlled data is concatenated or formatted into a SQL statement, allowing attackers to alter the query.",
         pat={"python": r"(?i)^(?=.*\b" + _SQL_KW + r"\b)(?=.*(\bf[\"']|[\"']\s*\+|\+\s*[\"']|[\"']\s*%\s*[\w(]|\.format\())",
              "java": r"(?i)(?=.*\b" + _SQL_KW + r"\b)(?=.*([\"']\s*\+|\+\s*[\"']))"}),
    dict(cat="hardcoded_secret", title="Hardcoded credential or secret", sev="High", cwe="CWE-798",
         owasp="A07:2021 Identification and Authentication Failures",
         desc="A secret is embedded in source code and will leak through version control.",
         pat=r"(?i)\b\w*" + _SECRET_NAME + r"\w*[\"']?\s*(=|:)\s*[\"'][^\"'\s]{4,}[\"']|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
    dict(cat="xss", title="Cross-site scripting (XSS): unescaped output", sev="High", cwe="CWE-79",
         owasp="A03:2021 Injection",
         desc="Untrusted data is rendered into HTML without encoding.",
         pat={"python": r"render_template_string\s*\(.*(f[\"']|\+|%|\.format|request\.)|\bMarkup\s*\(|\|\s*safe\b|mark_safe\(|return\s+f[\"'][^\"']*<[^\"']*\{|\.innerHTML\s*=",
              "java": r"\.(print|println|write)\(.*getParameter\(|\.(print|println|write)\(.*<.*[\"']\s*\+|\.innerHTML\s*="}),
    dict(cat="command_injection", title="OS command injection", sev="Critical", cwe="CWE-78",
         owasp="A03:2021 Injection",
         desc="A shell command is built from or executed with untrusted input.",
         pat={"python": r"\bos\.(system|popen)\(|subprocess\.\w+\(.*shell\s*=\s*True",
              "java": r"Runtime\.getRuntime\(\)\.exec\(.*\+|new\s+ProcessBuilder\(.*\+"}),
    dict(cat="code_injection", title="Dynamic code execution (eval/exec)", sev="High", cwe="CWE-94",
         owasp="A03:2021 Injection", desc="eval/exec can run attacker-controlled code.",
         pat={"python": r"(?<![\w.])(eval|exec)\s*\(", "java": r"ScriptEngine.*\.eval\("}),
    dict(cat="insecure_deserialization", title="Insecure deserialization", sev="High", cwe="CWE-502",
         owasp="A08:2021 Software and Data Integrity Failures",
         desc="Deserializing untrusted data can lead to remote code execution.",
         pat={"python": r"\b(pickle|cPickle|marshal)\.loads?\(|yaml\.load\((?!.*SafeLoader)",
              "java": r"new\s+ObjectInputStream\("}),
    dict(cat="weak_crypto", title="Weak cryptographic algorithm", sev="Medium", cwe="CWE-327",
         owasp="A02:2021 Cryptographic Failures",
         desc="A broken or weak algorithm (MD5, SHA-1, DES, RC4, ECB) is used.",
         pat={"python": r"hashlib\.(md5|sha1)\(|\b(DES|ARC4)\.new\(",
              "java": r"getInstance\(\s*\"(MD5|SHA-?1|DES|DESede|RC4)\"|\"AES/ECB"}),
    dict(cat="insecure_random", title="Predictable random generator used for a security value", sev="Medium",
         cwe="CWE-330", owasp="A07:2021 Identification and Authentication Failures",
         desc="Non-cryptographic PRNG used to generate a token, password, key or session value.",
         pat=r"(?i)(?=.*(random\.(random|randint|choice|randrange)\(|new\s+Random\(|Math\.random\())(?=.*(token|password|secret|session|otp|nonce|salt|key))"),
    dict(cat="path_traversal", title="Path traversal via user-controlled file path", sev="High", cwe="CWE-22",
         owasp="A01:2021 Broken Access Control",
         desc="A file path is built from user input without canonicalization and base-directory checks.",
         pat={"python": r"\b(open|send_file|send_from_directory)\(.*(request\.|input\(|sys\.argv)",
              "java": r"new\s+File(InputStream|Reader)?\(.*getParameter\("}),
    dict(cat="csrf", title="CSRF protection disabled", sev="Medium", cwe="CWE-352", owasp="A05:2021 Security Misconfiguration",
         desc="Anti-CSRF protection is explicitly turned off.",
         pat=r"@csrf_exempt|csrf\.exempt\(|WTF_CSRF_ENABLED\s*=\s*False|csrf\(\)\s*\.\s*disable\(|csrf\(.*disable"),
    dict(cat="ssl_verification", title="TLS certificate verification disabled", sev="High", cwe="CWE-295",
         owasp="A02:2021 Cryptographic Failures", desc="Disabling certificate checks allows man-in-the-middle attacks.",
         pat={"python": r"verify\s*=\s*False|ssl\._create_unverified_context",
              "java": r"ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts|X509TrustManager\s*\(\s*\)|setHostnameVerifier\(.*true"}),
    dict(cat="insecure_config", title="Insecure configuration (debug / permissive CORS)", sev="Medium", cwe="CWE-942",
         owasp="A05:2021 Security Misconfiguration",
         desc="Debug mode or wildcard CORS exposes the application.",
         pat=r"\.run\(.*debug\s*=\s*True|^\s*DEBUG\s*=\s*True|allow_origins\s*=\s*\[\s*[\"']\*|CORS\(.*origins\s*=\s*[\"']\*|@CrossOrigin\(.*\"\*\"|@CrossOrigin\s*$|setAllowedOrigins\(.*\"\*\""),
    dict(cat="insecure_auth", title="Plaintext password comparison", sev="High", cwe="CWE-256",
         owasp="A07:2021 Identification and Authentication Failures",
         desc="Passwords are compared as plaintext instead of verifying a salted hash.",
         pat={"python": r"(?i)\b(password|passwd|pwd)\w*\s*==\s*\S|\S\s*==\s*\w*(password|passwd|pwd)\b",
              "java": r"(?i)\b(password|passwd|pwd)\w*\.equals\(|\.equals\(\s*\w*(password|passwd|pwd)"}),
]

_AUTH_MARK = re.compile(r"login_required|requires_auth|jwt_required|permission_required|roles_required|auth_required|"
                        r"PreAuthorize|Secured|RolesAllowed|current_user|@authenticated", re.I)
_SENSITIVE = r"(admin|delete|remove|manage|internal)"
_ROUTE = {"python": re.compile(r"@\w+\.(route|get|post|put|delete|patch)\(.*" + _SENSITIVE, re.I),
          "java": re.compile(r"@(Get|Post|Put|Delete|Request|Patch)Mapping\(.*" + _SENSITIVE, re.I)}


def _is_comment(line: str, lang: str) -> bool:
    s = line.strip()
    return s.startswith("#") if lang == "python" else s.startswith(("//", "*", "/*"))


def run(sub) -> List[Finding]:
    lines, lang = sub.lines, sub.language
    out, seen = [], set()
    for i, line in enumerate(lines, 1):
        if _is_comment(line, lang):
            continue
        for r in RULES:
            pat = r["pat"].get(lang) if isinstance(r["pat"], dict) else r["pat"]
            if pat and re.search(pat, line) and (i, r["cat"]) not in seen:
                seen.add((i, r["cat"]))
                out.append(mk(A, r["cat"], r["title"], r["sev"], i, lines, r["desc"], r["cwe"], r["owasp"]))
        if _ROUTE[lang].search(line):
            window = lines[max(0, i - 4): i + 6]
            if not any(_AUTH_MARK.search(w) for w in window):
                out.append(mk(A, "broken_access_control", "Sensitive endpoint without authentication/authorization check",
                              "High", i, lines, "Admin/destructive endpoint has no visible auth or role check.",
                              "CWE-862", "A01:2021 Broken Access Control"))
    return out
