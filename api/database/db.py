import os
import logging
import json
from urllib.parse import urlparse
import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

DATABASE_URL = os.environ.get("DATABASE_URL")

# ----------------------
# Basic validation
# ----------------------
def _validate_database_url(url):
    if not url:
        raise RuntimeError("DATABASE_URL not set in environment")
    parsed = urlparse(url)
    if parsed.scheme not in ("postgres", "postgresql"):
        raise RuntimeError("DATABASE_URL must be a postgres connection string")
    if not parsed.hostname or not parsed.path:
        raise RuntimeError("DATABASE_URL missing hostname or database name")
    return url

if DATABASE_URL:
    _validate_database_url(DATABASE_URL)

_pool: SimpleConnectionPool | None = None

# ----------------------
# Connection pool
# ----------------------
def get_pool(minconn=1, maxconn=10):
    global _pool
    if _pool is None:
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL not set")
        _pool = SimpleConnectionPool(minconn, maxconn, dsn=DATABASE_URL)
    return _pool

def get_conn():
    return get_pool().getconn()

def release_conn(conn):
    if conn:
        try:
            get_pool().putconn(conn)
        except Exception:
            logger.exception("Failed to release connection")

# ----------------------
# Query helper
# ----------------------
def db_query(sql, params=None, fetchone=False, fetchall=False, commit=False):
    """
    Safe query execution:
    - Always parameterized
    - Rolls back on error
    - Releases connection
    """
    conn = None
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params or ())
            result = None
            if fetchone:
                result = cur.fetchone()
            elif fetchall:
                result = cur.fetchall()
            if commit:
                conn.commit()
            return result
    except psycopg2.Error:
        if conn:
            try:
                conn.rollback()
            except Exception:
                logger.exception("Failed to rollback connection")
        logger.exception("db_query failed for SQL: %s params: %s", sql, params)
        raise
    finally:
        release_conn(conn)

# ----------------------
# Input sanitization helpers
# ----------------------
def safe_str(val: str) -> str:
    """Strip whitespace and reject dangerous characters"""
    if not val or not isinstance(val, str):
        return ""
    val = val.strip()
    if len(val) > 255:
        val = val[:255]
    return val

def safe_json(val) -> dict:
    """Ensure JSON object, fallback to empty dict"""
    if isinstance(val, dict):
        return val
    try:
        return json.loads(val)
    except Exception:
        return {}

# ----------------------
# Table creation
# ----------------------
def ensure_tables():
    if not DATABASE_URL:
        logger.warning("DATABASE_URL not set; skipping table creation")
        return

    sql = """
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

    CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        encrypted_pass TEXT,
        verified BOOLEAN DEFAULT FALSE,
        role VARCHAR(50) DEFAULT 'client',
        meta JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        last_login TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS user_identities (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        provider VARCHAR(50) NOT NULL,
        provider_user_id TEXT NOT NULL,
        provider_profile JSONB,
        tokens JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (provider, provider_user_id)
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(10) NOT NULL CHECK (type IN ('Buy','Sell')),
        stock VARCHAR(32) NOT NULL,
        quantity INTEGER NOT NULL CHECK (quantity > 0),
        price NUMERIC(20,4) NOT NULL CHECK (price >= 0),
        date DATE NOT NULL,
        notes TEXT,
        source VARCHAR(50),
        created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_transactions_user_stock ON transactions(user_id, stock);
    """

    conn = None
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute(sql)
            conn.commit()
    except Exception:
        logger.exception("Failed to ensure tables")
        if conn:
            conn.rollback()
        raise
    finally:
        release_conn(conn)
