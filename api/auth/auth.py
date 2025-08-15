# api/auth/auth.py
import os
import logging
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import jsonify, request, make_response
from flask_login import LoginManager, UserMixin, current_user

from api.database.db import db_query

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

login_manager = LoginManager()
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-default-secret-key')


class User(UserMixin):
    def __init__(self, user_id, email=None):
        self.id = str(user_id)
        self.email = email


@login_manager.user_loader
def load_user(user_id):
    try:
        row = db_query("SELECT id, email, verified FROM users WHERE id = %s", (user_id,), fetchone=True)
        if not row:
            return None
        return User(row['id'], row.get('email'))
    except Exception as e:
        logger.exception("load_user error: %s", e)
        return None


def get_user_by_email(email):
    if not email:
        return None
    try:
        row = db_query("SELECT * FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
        return dict(row) if row else None
    except Exception as e:
        logger.exception("get_user_by_email error: %s", e)
        return None


def get_user_by_id(user_id):
    try:
        row = db_query("SELECT * FROM users WHERE id = %s LIMIT 1", (user_id,), fetchone=True)
        return dict(row) if row else None
    except Exception as e:
        logger.exception("get_user_by_id error: %s", e)
        return None


def generate_jwt(user_id, days_valid=1):
    payload = {
        "user_id": str(user_id),
        "exp": datetime.utcnow() + timedelta(days=days_valid),
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token


def verify_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload.get("user_id")
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """
    Decorator to protect endpoints. Accepts Bearer token Authorization header or Flask-Login session.
    Returns 401 with CORS headers set if missing/invalid.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Handle preflight quickly
        if request.method == 'OPTIONS':
            response = make_response()
            origin = request.headers.get('Origin', '*')
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Methods'] = "GET,POST,OPTIONS"
            response.headers['Access-Control-Allow-Headers'] = "Content-Type, Authorization"
            response.headers['Access-Control-Allow-Credentials'] = "true"
            return response

        auth_header = request.headers.get('Authorization', '')
        user_id = None
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1].strip()
            user_id = verify_jwt(token)

        # fallback to Flask-Login session
        if not user_id:
            try:
                if current_user and current_user.is_authenticated:
                    user_id = current_user.id
            except Exception as e:
                logger.exception("Error checking Flask-Login session: %s", e)
                user_id = None

        if not user_id:
            response = jsonify({'success': False, 'error': 'Token is missing or user not authenticated!'})
            response.status_code = 401
            origin = request.headers.get('Origin', '*')
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response

        # verify user exists in DB
        u = get_user_by_id(user_id)
        if not u:
            response = jsonify({'success': False, 'error': 'Invalid or expired token!'})
            response.status_code = 401
            origin = request.headers.get('Origin', '*')
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response

        # call endpoint with user_id injected
        return f(user_id, *args, **kwargs)
    return decorated
