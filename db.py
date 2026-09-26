"""
Database connection handling for the UEBA system.

Reads connection info from the DATABASE_URL environment variable, e.g.:
    postgresql://ueba_user:secret@localhost:5432/ueba

Falls back to sensible local defaults if not set.
"""
import os
import contextlib
import psycopg2
import psycopg2.extras
import psycopg2.pool

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/ueba",
)

_MIN_CONN = int(os.environ.get("UEBA_DB_POOL_MIN", "1"))
_MAX_CONN = int(os.environ.get("UEBA_DB_POOL_MAX", "10"))

_pool = None


def init_pool():
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(_MIN_CONN, _MAX_CONN, dsn=DATABASE_URL)
    return _pool


@contextlib.contextmanager
def get_conn():
    """Context manager yielding a pooled connection. Commits on success,
    rolls back on exception, always returns the connection to the pool."""
    pool = init_pool()
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


@contextlib.contextmanager
def get_cursor(dict_cursor=True):
    """Convenience context manager yielding (conn, cursor)."""
    with get_conn() as conn:
        cursor_factory = psycopg2.extras.RealDictCursor if dict_cursor else None
        cur = conn.cursor(cursor_factory=cursor_factory)
        try:
            yield conn, cur
        finally:
            cur.close()
