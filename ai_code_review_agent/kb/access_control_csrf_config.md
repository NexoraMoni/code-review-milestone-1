# Access Control, CSRF and Secure Configuration

## Broken access control
Every sensitive route needs authentication and authorization. In Flask use login_required plus role checks; in Spring use PreAuthorize or Secured and method security. Verify object ownership for each record to prevent IDOR. Deny by default. CWE-862, OWASP A01:2021.

## CSRF
State-changing requests must carry an anti-CSRF token or use SameSite cookies. Do not use csrf_exempt, disable CSRFProtect, or call csrf().disable() in Spring Security for browser-facing apps. CWE-352.

## Misconfiguration
Disable debug mode in production, restrict CORS to specific trusted origins instead of a wildcard, and keep security headers enabled. CWE-16, CWE-942, OWASP A05:2021.

## Authentication
Compare passwords by verifying hashes with check_password_hash, bcrypt.checkpw or a Spring PasswordEncoder; never compare plaintext with equality operators. CWE-256, CWE-287.
