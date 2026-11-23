# Cryptography and Secure Randomness

## Weak algorithms
MD5 and SHA-1 are broken for security use; DES, 3DES, RC4 and ECB mode are weak. CWE-327, CWE-328. Use SHA-256 or stronger for integrity, and AES-GCM for encryption. Store passwords with bcrypt, scrypt or Argon2 using per-user salts, not fast hashes.

## Insecure randomness
random.random, random.choice and java.util.Random are predictable and must not generate tokens, passwords, session ids or OTPs. CWE-330. Use Python secrets (token_urlsafe, token_hex) or Java SecureRandom.

## TLS
Never disable certificate or hostname verification (verify=False, trust-all managers). CWE-295.
