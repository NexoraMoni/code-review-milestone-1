"""Milestone 3 - Remediation Agent: per-finding fix guidance + corrected code, grounded in the KB.
Uses Claude when an API key is present; otherwise curated templates + RAG context."""
from concurrent.futures import ThreadPoolExecutor
from typing import List
from ..models import Finding, SEV_RANK

T = {
 "sql_injection": ("Use parameterized queries so user input is bound as data, never as SQL syntax.",
  {"python": 'cursor.execute("SELECT id, name FROM users WHERE name = ?", (name,))  # bound parameter',
   "java": 'String sql = "SELECT id, name FROM users WHERE name = ?";\ntry (PreparedStatement ps = conn.prepareStatement(sql)) {\n    ps.setString(1, name);\n    try (ResultSet rs = ps.executeQuery()) { /* ... */ }\n}'}),
 "hardcoded_secret": ("Move the secret to environment variables or a secrets manager and rotate the exposed value.",
  {"python": 'import os\nAPI_KEY = os.environ["API_KEY"]   # injected at deploy time; rotate the leaked key',
   "java": 'String apiKey = System.getenv("API_KEY");   // or Spring @Value("${api.key}") / Vault'}),
 "xss": ("Escape output for its HTML context; use auto-escaping templates and avoid raw HTML sinks.",
  {"python": 'from flask import render_template\nreturn render_template("greeting.html", name=name)   # {{ name }} is auto-escaped',
   "java": 'import org.owasp.encoder.Encode;\nresponse.getWriter().print(Encode.forHtml(userInput));'}),
 "command_injection": ("Avoid the shell: pass arguments as a list and validate input against an allow-list.",
  {"python": 'import subprocess\nsubprocess.run(["ping", "-c", "1", validated_host], check=True, shell=False)',
   "java": 'ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", validatedHost);\npb.redirectErrorStream(true);\nProcess p = pb.start();'}),
 "code_injection": ("Replace eval/exec with safe parsing or an explicit dispatch table.",
  {"python": 'import ast\nvalue = ast.literal_eval(user_text)   # literals only\n# or: OPS = {"add": add, "sub": sub}; OPS[name](a, b)',
   "java": '// Use a whitelist-based dispatch (Map<String, Function<...>>) instead of evaluating scripts.'}),
 "insecure_deserialization": ("Deserialize only data formats (JSON) or enforce strict allow-lists.",
  {"python": 'import json, yaml\ndata = json.loads(payload)\nconfig = yaml.safe_load(stream)',
   "java": 'ObjectInputStream in = new ObjectInputStream(stream);\nin.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.myapp.dto.*;!*"));\n// better: use Jackson with typed DTOs'}),
 "weak_crypto": ("Use SHA-256+ for integrity, AES-GCM for encryption and bcrypt/Argon2 for passwords.",
  {"python": 'import hashlib, bcrypt\ndigest = hashlib.sha256(data).hexdigest()\npw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
   "java": 'MessageDigest md = MessageDigest.getInstance("SHA-256");\nCipher c = Cipher.getInstance("AES/GCM/NoPadding");'}),
 "insecure_random": ("Use a cryptographically secure random source for any security-relevant value.",
  {"python": 'import secrets\ntoken = secrets.token_urlsafe(32)',
   "java": 'SecureRandom rng = new SecureRandom();\nbyte[] b = new byte[32]; rng.nextBytes(b);\nString token = Base64.getUrlEncoder().withoutPadding().encodeToString(b);'}),
 "path_traversal": ("Canonicalize the path and verify it stays inside the permitted base directory.",
  {"python": 'from pathlib import Path\nBASE = Path("/srv/files").resolve()\ntarget = (BASE / name).resolve()\nif BASE not in target.parents:\n    abort(400)',
   "java": 'Path base = Paths.get("/srv/files").toRealPath();\nPath target = base.resolve(name).normalize();\nif (!target.startsWith(base)) throw new SecurityException("Invalid path");'}),
 "csrf": ("Keep CSRF protection enabled and send the token with every state-changing request.",
  {"python": 'from flask_wtf import CSRFProtect\ncsrf = CSRFProtect(app)   # remove @csrf_exempt',
   "java": 'http.csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));'}),
 "ssl_verification": ("Always verify TLS certificates; pin a CA bundle if you use a private CA.",
  {"python": 'requests.get(url, verify=True, timeout=10)   # or verify="/path/to/ca-bundle.pem"',
   "java": '// Use the JVM default TrustManager / HostnameVerifier; import private CAs into a truststore.'}),
 "insecure_config": ("Disable debug in production and restrict CORS to explicit trusted origins.",
  {"python": 'app.run(debug=False)   # read from env: debug=os.getenv("FLASK_DEBUG") == "1"\nCORS(app, origins=["https://app.example.com"])',
   "java": '@CrossOrigin(origins = "https://app.example.com")'}),
 "insecure_auth": ("Verify salted password hashes using a constant-time check.",
  {"python": 'from werkzeug.security import check_password_hash\nif user and check_password_hash(user.password_hash, password):\n    ...',
   "java": 'if (passwordEncoder.matches(rawPassword, user.getPasswordHash())) { /* ... */ }'}),
 "broken_access_control": ("Require authentication and an explicit role check on sensitive endpoints; deny by default.",
  {"python": '@app.route("/admin/delete/<int:uid>", methods=["POST"])\n@login_required\n@roles_required("admin")\ndef delete_user(uid): ...',
   "java": '@PreAuthorize("hasRole(\'ADMIN\')")\n@DeleteMapping("/admin/users/{id}")\npublic void deleteUser(@PathVariable long id) { /* ... */ }'}),
 "long_function": ("Split the function into small, single-purpose helpers.",
  {"any": "def process(order):\n    validate(order)\n    total = price(order)\n    return persist(order, total)   # each step in its own function"}),
 "high_complexity": ("Reduce branching with guard clauses, lookup tables or strategy objects.",
  {"any": "RATES = {\"gold\": 0.2, \"silver\": 0.1}\ndef discount(tier):\n    return RATES.get(tier, 0.0)   # replaces an if/elif chain"}),
 "deep_nesting": ("Return early and invert conditions to flatten the control flow.",
  {"any": "if not user:\n    return None\nif not user.active:\n    return None\nreturn compute(user)"}),
 "many_params": ("Group related parameters into a dataclass / parameter object.",
  {"python": "@dataclass\nclass OrderRequest:\n    customer: str\n    items: list\n    coupon: str | None = None\n\ndef process(req: OrderRequest): ...",
   "java": "public record OrderRequest(String customer, List<Item> items, String coupon) {}\nvoid process(OrderRequest req) { /* ... */ }"}),
 "bare_except": ("Catch specific exceptions and log them with context.",
  {"python": 'try:\n    risky()\nexcept (ValueError, KeyError):\n    logger.exception("risky() failed")\n    raise'}),
 "mutable_default": ("Default to None and build the mutable object inside the function.",
  {"python": "def add(item, bucket=None):\n    bucket = [] if bucket is None else bucket\n    bucket.append(item)\n    return bucket"}),
 "missing_docstring": ("Add a concise docstring describing purpose, parameters and return value.",
  {"python": 'def total(items):\n    """Return the sum of item prices."""'}),
 "wildcard_import": ("Import only the names you use.",
  {"python": "from math import sqrt, ceil", "java": "import java.util.List;\nimport java.util.Map;"}),
 "god_class": ("Split the class by responsibility (e.g. repository, service, validator).",
  {"any": "class UserRepository: ...\nclass UserValidator: ...\nclass UserService: ..."}),
 "empty_catch": ("Never swallow exceptions: log, handle or rethrow with context.",
  {"python": 'except Exception:\n    logger.exception("operation failed")\n    raise',
   "java": 'catch (IOException e) {\n    log.error("Operation failed", e);\n    throw new UncheckedIOException(e);\n}'}),
 "generic_catch": ("Catch the most specific exception types you can handle.",
  {"java": 'catch (SQLException | IOException e) {\n    log.error("failed", e);\n}'}),
 "print_statement": ("Use a logging framework with levels instead of printing.",
  {"python": 'import logging\nlogger = logging.getLogger(__name__)\nlogger.info("processing %s", item)',
   "java": 'private static final Logger log = LoggerFactory.getLogger(MyClass.class);\nlog.info("processing {}", item);'}),
 "public_field": ("Make fields private and expose them via accessors.",
  {"java": "private String name;\npublic String getName() { return name; }"}),
 "global_state": ("Pass state explicitly or encapsulate it in a class.",
  {"python": "class Counter:\n    def __init__(self):\n        self.value = 0"}),
 "long_lines": ("Wrap long lines at ~100-120 characters and extract expressions into named variables.", {"any": ""}),
 "todo": ("Convert TODO/FIXME comments into tracked issues and resolve them.", {"any": ""}),
}


def _template(f: Finding, lang: str):
    text, code = T.get(f.category, ("Review and fix according to secure coding guidelines.", {}))
    return text, code.get(lang) or code.get("any") or ""


def _one(f: Finding, lang: str, kb, llm):
    query = f"{f.title} {f.category.replace('_', ' ')} {f.cwe} {f.owasp}"
    hits = kb.search(query, k=2)
    f.references = sorted({c.source for c, _ in hits})
    text, code = _template(f, lang)
    if llm is not None and llm.available:
        try:
            ctx = "\n\n".join(c.text for c, _ in hits)
            res = llm.complete_json(
                "You are a senior application-security engineer. Give a precise fix for the flagged code, grounded in the context.",
                f"Language: {lang}\nFinding: {f.title} ({f.cwe})\nLine {f.line}: {f.snippet}\n\nGuidelines:\n{ctx}\n\n"
                'Return JSON: {"remediation": "<2-3 sentences>", "fixed_code": "<corrected code only>"}')
            text, code = res.get("remediation", text), res.get("fixed_code", code)
        except Exception:
            pass
    elif hits:
        text += " Guideline: " + hits[0][0].text.split(". ")[0].strip(". ") + "."
    f.remediation, f.fixed_code = text, code


def run(findings: List[Finding], lang: str, kb, llm=None, max_llm: int = 15) -> List[Finding]:
    ordered = sorted(findings, key=lambda f: SEV_RANK[f.severity])
    with ThreadPoolExecutor(max_workers=4) as ex:
        for i, f in enumerate(ordered):
            ex.submit(_one, f, lang, kb, llm if i < max_llm else None)
    return findings
