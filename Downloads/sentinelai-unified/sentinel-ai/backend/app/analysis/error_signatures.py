"""
SentinelAI - Phase 6: Response Intelligence Engine
Error-signature matching.

Purely pattern-based recognition of well-known framework/database error
strings appearing in a response body. This is an *indicator*, not a
vulnerability claim -- Section 13 (False Positive Engine) explicitly
requires that "a database-looking error alone should NOT automatically
mean SQL injection."
"""

from __future__ import annotations

import re

# (signature_name, compiled pattern) -- intentionally generic/well-known
# error strings, not exploit payloads.
_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("mysql", re.compile(r"you have an error in your sql syntax", re.I)),
    ("mysql", re.compile(r"warning: mysqli?_", re.I)),
    ("postgresql", re.compile(r"pg_query\(\)|PostgreSQL.*ERROR", re.I)),
    ("mssql", re.compile(r"unclosed quotation mark after the character string", re.I)),
    ("oracle", re.compile(r"ORA-\d{4,5}", re.I)),
    ("sqlite", re.compile(r"sqlite3\.OperationalError|SQLite/JDBCDriver", re.I)),
    ("php", re.compile(r"Fatal error:|Warning:.*on line \d+", re.I)),
    ("java_stacktrace", re.compile(r"at [\w.$]+\([\w.]+:\d+\)"), ),
    ("python_traceback", re.compile(r"Traceback \(most recent call last\)", re.I)),
    ("dotnet", re.compile(r"System\.\w*Exception", re.I)),
    ("generic_path_disclosure", re.compile(r"(?:/var/www|/usr/local|[A-Z]:\\\\(?:inetpub|xampp|wamp))", re.I)),
]


def detect_error_signature(body: str) -> str | None:
    """Return the first matching signature name, or None. Only ever
    returns a label -- callers decide what (if anything) that implies."""
    if not body:
        return None
    for name, pattern in _SIGNATURES:
        if pattern.search(body):
            return name
    return None
