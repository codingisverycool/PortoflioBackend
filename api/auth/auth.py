# api/auth/auth.py
import os
import logging
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import request, jsonify, make_response

from api.database.db import db_query

# ----------------------
# Logging
# ----------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(
    logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
)
if not logger.handlers:
    logger.addHandler(handler)

# ----------------------
# Environment variables
# ----------------------
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
if not JWT_SECRET_KEY or len(JWT_SECRET_KEY) < 32:
    raise ValueError("JWT_SECRET_KEY must be at least 32 characters long")

JWT_ALGORITHM = os.environ.get('JWT_ALGORITHM', 'HS256')
JWT_EXPIRE_DAYS = int(os.environ.get('JWT_EXPIRE_DAYS', 7))
COOKIE_NAME = os.environ.get('COOKIE_NAME', 'access_token')

# ----------------------
# Helper functions
# ----------------------
def get_user_by_email(email):
    if not email or not isinstance(email, str):
        return None
    try:
        email = email.strip().lower()
        row = db_query(
            "SELECT * FROM users WHERE email = %s LIMIT 1",
            (email,),
            fetchone=True
        )
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching user by email {email}: {str(e)}")
        return None

def get_user_by_id(user_id):
    if not user_id:
        return None
    try:
        row = db_query(
            "SELECT * FROM users WHERE id = %s LIMIT 1",
            (user_id,),
            fetchone=True
        )
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching user by ID {user_id}: {str(e)}")
        return None

def verify_jwt(token):
    """
    Verifies a JWT from NextAuth (backend-generated) or custom-issued.
    Accepts both "user_id" and "sub" as identifiers.
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_aud": False, "verify_iss": False}  # don’t enforce iss/aud
        )

        user_id = payload.get("user_id") or payload.get("sub")
        if not user_id:
            logger.warning(f"JWT missing user_id/sub: {payload}")
            return None

        logger.info(f"JWT verified successfully for user_id={user_id}")
        return user_id
    except jwt.ExpiredSignatureError:
        logger.warning("Expired JWT token")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"JWT verification error: {str(e)}")
        return None

# ----------------------
# Token retrieval helper
# ----------------------
def get_token_from_request():
    """
    Attempt to obtain a JWT token from:
      1) Authorization header: 'Bearer <token>'
      2) HttpOnly cookie named COOKIE_NAME
    Returns (token, source) or (None, None).
    """
    auth = request.headers.get('Authorization', '')
    if auth and auth.startswith('Bearer '):
        token = auth.split(' ', 1)[1].strip()
        if token:
            return token, 'header'

    token = request.cookies.get(COOKIE_NAME)
    if token:
        return token, 'cookie'

    return None, None

# ----------------------
# Decorators
# ----------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            resp = make_response()
            origin = request.headers.get('Origin', '*')
            resp.headers['Access-Control-Allow-Origin'] = origin
            resp.headers['Access-Control-Allow-Methods'] = "GET, POST, PUT, DELETE, OPTIONS"
            resp.headers['Access-Control-Allow-Headers'] = "Content-Type, Authorization, X-Requested-With"
            resp.headers['Access-Control-Allow-Credentials'] = "true"
            resp.headers['Access-Control-Max-Age'] = "86400"
            return resp

        token, source = get_token_from_request()
        user_id = None

        if token:
            user_id = verify_jwt(token)
            logger.info(f"JWT auth attempt from {source}: user_id={user_id}")

        if not user_id:
            resp = jsonify({'success': False, 'error': 'Authentication required', 'code': 'UNAUTHORIZED'})
            resp.status_code = 401
            origin = request.headers.get('Origin', '*')
            resp.headers['Access-Control-Allow-Origin'] = origin
            resp.headers['Access-Control-Allow-Credentials'] = 'true'
            return resp

        user = get_user_by_id(user_id)
        if not user:
            resp = jsonify({'success': False, 'error': 'Invalid user', 'code': 'USER_NOT_FOUND'})
            resp.status_code = 401
            origin = request.headers.get('Origin', '*')
            resp.headers['Access-Control-Allow-Origin'] = origin
            resp.headers['Access-Control-Allow-Credentials'] = 'true'
            return resp

        request.user = user
        return f(user_id, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(user_id, *args, **kwargs):
        user = get_user_by_id(user_id)
        if not user or user.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required', 'code': 'FORBIDDEN'}), 403
        return f(user_id, *args, **kwargs)
    return decorated

# ----------------------
# Optional: generate JWT (for testing)
# ----------------------
def generate_jwt(user_id, expires_days=JWT_EXPIRE_DAYS):
    payload = {
        "user_id": str(user_id),
        "exp": datetime.utcnow() + timedelta(days=expires_days),
        "iat": datetime.utcnow(),
    }
    try:
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return token if isinstance(token, str) else token.decode('utf-8')
    except Exception as e:
        logger.error(f"JWT generation failed: {str(e)}")
        raise
