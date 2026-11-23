# OS Command Injection and Code Injection

## What it is
Passing untrusted input to a shell, to eval or exec, or to Runtime.exec lets attackers run arbitrary commands. CWE-78, CWE-94, OWASP A03:2021.

## Defence
Avoid shell invocation. In Python call subprocess.run with a list of arguments and shell=False; never use os.system or shell=True with user data. In Java use ProcessBuilder with separate argument elements rather than concatenated command strings. Validate input against an allow-list. Replace eval and exec with ast.literal_eval, json parsing or a dispatch dictionary of permitted operations.
