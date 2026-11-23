# OWASP Top 10 (2021) Overview

## A01 Broken Access Control
Users act outside their intended permissions. Enforce authorization on the server for every request, deny by default, check object ownership to prevent IDOR, and protect admin or destructive endpoints with role checks. CWE-284, CWE-862, CWE-639.

## A02 Cryptographic Failures
Sensitive data is exposed through weak or missing cryptography. Avoid MD5, SHA-1, DES, RC4 and ECB mode. Hash passwords with bcrypt, scrypt or Argon2. Use TLS everywhere and never disable certificate verification. CWE-327, CWE-328, CWE-295.

## A03 Injection
Untrusted data is sent to an interpreter as part of a command or query. Covers SQL injection, OS command injection, code injection and cross-site scripting. Use parameterized APIs, allow-list validation, and context-aware output encoding. CWE-89, CWE-78, CWE-79, CWE-94.

## A04 Insecure Design
Missing security controls at design time. Use threat modelling, secure design patterns and abuse-case testing.

## A05 Security Misconfiguration
Debug mode in production, permissive CORS, default credentials and disabled security features such as CSRF protection. CWE-16, CWE-942, CWE-352.

## A06 Vulnerable and Outdated Components
Keep dependencies patched; use software composition analysis.

## A07 Identification and Authentication Failures
Plaintext password storage or comparison, weak session tokens, missing brute-force protection. Compare password hashes with constant-time functions and generate tokens with a cryptographically secure random source. CWE-287, CWE-798, CWE-330.

## A08 Software and Data Integrity Failures
Insecure deserialization (pickle, yaml.load, Java ObjectInputStream) lets attackers execute code. Use safe data formats such as JSON and verify integrity. CWE-502.

## A09 Logging and Monitoring Failures
Log security events without leaking secrets; never swallow exceptions silently. CWE-778, CWE-532.

## A10 Server-Side Request Forgery
Validate and allow-list outbound URLs fetched on behalf of users. CWE-918.
