import os
import logging
import jwt
from functools import wraps
from datetime import datetime, timedelta
from flask import request, jsonify, make_response
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
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
# User helpers
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

# ----------------------
# Google JWT verification (used only at login)
# ----------------------
def verify_google_jwt(token):
    try:
        CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
        payload = id_token.verify_oauth2_token(token, google_requests.Request(), CLIENT_ID)
        user_id = payload.get("sub")
        if not user_id:
            logger.warning(f"Google JWT missing 'sub': {payload}")
            return None
        logger.info(f"Google JWT verified successfully for user_id={user_id}")
        return payload  # return full payload
    except ValueError as e:
        logger.warning(f"Invalid Google JWT: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error verifying Google JWT: {str(e)}")
        return None

# ----------------------
# Backend JWT helpers
# ----------------------
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
JWT_EXP_HOURS = 24

def generate_jwt(user_id):
    payload = {
        "user_id": str(user_id),
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXP_HOURS)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def verify_jwt(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload.get("user_id")
    except jwt.ExpiredSignatureError:
        logger.warning("JWT expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid JWT")
        return None

# ----------------------
# Token retrieval helper
# ----------------------
def get_token_from_request():
    auth = request.headers.get('Authorization', '')
    if auth and auth.startswith('Bearer '):
        token = auth.split(' ', 1)[1].strip()
        if token:
            return token
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

        token = get_token_from_request()
        if not token:
            resp = jsonify({'success': False, 'error': 'Authentication required', 'code': 'UNAUTHORIZED'})
            resp.status_code = 401
            origin = request.headers.get('Origin', '*')
            resp.headers['Access-Control-Allow-Origin'] = origin
            resp.headers['Access-Control-Allow-Credentials'] = 'true'
            return resp

        user_id = verify_jwt(token)
        if not user_id:
            resp = jsonify({'success': False, 'error': 'Invalid or expired token', 'code': 'UNAUTHORIZED'})
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
