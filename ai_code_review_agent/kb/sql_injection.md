# SQL Injection Prevention

## What it is
SQL injection happens when user input is concatenated, formatted or interpolated into a SQL string, letting an attacker change the query structure and read, modify or delete data. CWE-89, OWASP A03:2021.

## Defence
Always use parameterized queries (prepared statements) so the database treats input strictly as data. In Python use placeholders with the DB-API such as cursor.execute with a tuple of parameters; never use f-strings, percent formatting, plus concatenation or str.format to build SQL. In Java use PreparedStatement with setString or setInt; never build queries with Statement and string concatenation. ORMs such as SQLAlchemy and JPA with named parameters also bind values safely.

## Additional layers
Apply least-privilege database accounts, validate input types and lengths with allow-lists, and avoid exposing raw database errors to users. Identifiers such as table or column names cannot be parameterized, so map them from an allow-list.
