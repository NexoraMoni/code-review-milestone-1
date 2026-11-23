"""Sample 1 (low complexity, clean): small utility module."""
import logging
import sqlite3

logger = logging.getLogger(__name__)


def average(values):
    """Return the arithmetic mean of a list of numbers."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def get_user(conn: sqlite3.Connection, user_id: int):
    """Fetch a user row using a parameterized query."""
    cur = conn.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()
