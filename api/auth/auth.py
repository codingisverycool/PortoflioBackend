# api/auth/auth.py 
import os
import logging
import jwt
from functools import wraps
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
# Helper functions
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
# Verify backend JWT
# ----------------------
def verify_backend_jwt(token):
    """
    Verifies a JWT signed by this backend.
    Returns the decoded payload if valid, else None.
    """
    try:
        secret = os.environ.get("SECRET_KEY")
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Backend JWT expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid backend JWT: {str(e)}")
        return None

# ----------------------
# Token retrieval helper
# ----------------------
def get_token_from_request():
    """
    Attempt to obtain a JWT token from Authorization header: 'Bearer <token>'
    Returns (token, source) or (None, None).
    """
    auth = request.headers.get('Authorization', '')
    if auth and auth.startswith('Bearer '):
        token = auth.split(' ', 1)[1].strip()
        if token:
            return token, 'header'
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

        # Get token from header
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            resp = jsonify({'success': False, 'error': 'Authentication required', 'code': 'UNAUTHORIZED'})
            resp.status_code = 401
            return resp

        token = auth.split(' ', 1)[1].strip()
        if not token:
            resp = jsonify({'success': False, 'error': 'Authentication required', 'code': 'UNAUTHORIZED'})
            resp.status_code = 401
            return resp

        # 🔑 Verify backend JWT
        payload = verify_backend_jwt(token)
        if not payload:
            resp = jsonify({'success': False, 'error': 'Invalid token', 'code': 'UNAUTHORIZED'})
            resp.status_code = 401
            return resp

        # Extract user_id from payload
        user_id = payload.get('user_id')
        if not user_id:
            resp = jsonify({'success': False, 'error': 'Invalid token payload', 'code': 'UNAUTHORIZED'})
            resp.status_code = 401
            return resp

        # Get user from DB
        user = get_user_by_id(user_id)
        if not user:
            resp = jsonify({'success': False, 'error': 'User not found', 'code': 'USER_NOT_FOUND'})
            resp.status_code = 401
            return resp
        
        print("Authorization header:", request.headers.get("Authorization"))
        print("Decoded payload:", payload)

        request.user = user
        return f(user['id'], *args, **kwargs)

    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(user_id, *args, **kwargs):
        user = get_user_by_id(user_id)
        if not user or user.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required', 'code': 'FORBIDDEN'}), 403
        return f(user_id, *args, **kwargs)
    return decorated
