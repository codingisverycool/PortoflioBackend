# api/auth/auth.py
import os
import logging
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import request, jsonify, make_response
from flask_login import current_user

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
logger.addHandler(handler)

# ----------------------
# Env variables
# ----------------------
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
if not JWT_SECRET_KEY or len(JWT_SECRET_KEY) < 32:
    raise ValueError("JWT_SECRET_KEY must be at least 32 characters long")

JWT_ALGORITHM = os.environ.get('JWT_ALGORITHM', 'HS256')
JWT_EXPIRE_DAYS = int(os.environ.get('JWT_EXPIRE_DAYS', 7))

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

def generate_jwt(user_id, expires_days=JWT_EXPIRE_DAYS):
    payload = {
        "user_id": str(user_id),
        "exp": datetime.utcnow() + timedelta(days=expires_days),
        "iat": datetime.utcnow(),
        "iss": "your-app-name",
        "aud": "your-app-client"
    }
    try:
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return token if isinstance(token, str) else token.decode('utf-8')
    except Exception as e:
        logger.error(f"JWT generation failed: {str(e)}")
        raise

def verify_jwt(token):
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            issuer="your-app-name",
            audience="your-app-client"
        )
        return payload.get("user_id")
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

        auth_header = request.headers.get('Authorization', '')
        user_id = None

        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1].strip()
            user_id = verify_jwt(token)
            logger.info(f"JWT auth attempt for user: {user_id}")

        if not user_id:
            try:
                if current_user.is_authenticated:
                    user_id = current_user.id
                    logger.info(f"Session auth for user: {user_id}")
            except Exception as e:
                logger.warning(f"Session auth check failed: {str(e)}")

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
