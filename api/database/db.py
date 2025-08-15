# api/database/db.py
import os
import logging
import json
import re
from urllib.parse import urlparse

import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

DATABASE_URL = os.environ.get('DATABASE_URL')

# Basic validation of DATABASE_URL to avoid misuse or accidental exposing (not a replacement for proper infra)
def _validate_database_url(url):
    if not url:
        raise RuntimeError("DATABASE_URL not set. Set it in environment.")
    parsed = urlparse(url)
    if parsed.scheme not in ('postgres', 'postgresql'):
        raise RuntimeError("DATABASE_URL must be a postgres connection string.")
    # Minimal safety check: do not allow arbitrary file paths etc in connection string
    return url

if DATABASE_URL:
    _validate_database_url(DATABASE_URL)

_pool = None

def get_pool(minconn=1, maxconn=10):
    """
    Create or return a connection pool.
    Use parameterized min/max connections so tests can override if needed.
    """
    global _pool
    if _pool is None:
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL not set. Set it in environment.")
        # Use sslmode if provided via env (Vercel / managed PG may require)
        _pool = SimpleConnectionPool(minconn, maxconn, dsn=DATABASE_URL)
    return _pool

def get_conn():
    """
    Get a connection from the pool. Caller must call release_conn(conn) when finished.
    """
    return get_pool().getconn()

def release_conn(conn):
    """
    Put conn back in pool. Safe to call even if conn is None.
    """
    try:
        if conn:
            get_pool().putconn(conn)
    except Exception:
        logger.exception("Error releasing DB connection")

def db_query(sql, params=None, fetchone=False, fetchall=False, commit=False):
    """
    Generic DB helper. Uses parameterized queries only (pass params tuple/list).
    Rolls back on exception and always releases connection back to pool.
    Avoids SQL injection by never formatting SQL with string interpolation.
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
    except Exception:
        try:
            if conn:
                conn.rollback()
        except Exception:
            logger.exception("Failed to rollback connection after error")
        logger.exception("db_query failed for SQL: %s params: %s", sql, params)
        raise
    finally:
        release_conn(conn)


def ensure_tables():
    """Create required tables if they don't exist."""
    if not DATABASE_URL:
        logger.warning("DATABASE_URL not set; skipping table creation.")
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

    CREATE TABLE IF NOT EXISTS user_risk_profiles (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        profile_json JSONB NOT NULL,
        total_score INTEGER,
        risk_bracket VARCHAR(100),
        created_at TIMESTAMPTZ DEFAULT NOW()
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
    finally:
        release_conn(conn)
