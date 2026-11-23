# Secrets Management and Hardcoded Credentials

## What it is
Passwords, API keys, tokens and private keys committed in source code are exposed to everyone with repository access and remain in version history. CWE-798, OWASP A07:2021.

## Defence
Load secrets from environment variables or a secrets manager such as HashiCorp Vault, AWS Secrets Manager or Azure Key Vault. Never commit secrets; add .env files to .gitignore. Rotate any credential that has ever been committed. Use secret scanning (gitleaks, trufflehog) in CI. In Python read os.environ; in Java read System.getenv or Spring externalized configuration.
