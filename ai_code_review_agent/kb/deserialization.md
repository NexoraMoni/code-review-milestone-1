# Insecure Deserialization

## What it is
Deserializing untrusted data with pickle, marshal, yaml.load or Java ObjectInputStream can execute attacker-chosen code. CWE-502, OWASP A08:2021.

## Defence
Prefer data-only formats such as JSON. Use yaml.safe_load instead of yaml.load. Never unpickle data from untrusted sources; sign data with HMAC if pickle is unavoidable. In Java use ObjectInputFilter allow-lists or switch to Jackson or Gson with typed classes.
