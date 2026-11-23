# Path Traversal

## What it is
Using user-supplied filenames in file paths lets attackers read files outside the intended directory with sequences like ../. CWE-22.

## Defence
Resolve the final path and verify it stays inside the base directory. In Python use pathlib resolve and check parents; in Java use Path.normalize and startsWith. Prefer opaque identifiers mapped to stored files, and use werkzeug secure_filename for uploads.
