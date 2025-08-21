# api/auth/auth.py
import os
import logging
import jwt
from datetime import datetime, timedelta
from functools import wraps
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
# Verify Google ID Token
# Only used at login
# ----------------------
def verify_google_jwt(token):
    """
    Verifies a Google ID token (JWT) using google-auth library.
    Returns the Google 'sub' field (user ID) if valid, else None.
    """
    try:
        CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
        payload = id_token.verify_oauth2_token(token, google_requests.Request(), CLIENT_ID)
        user_id = payload.get("sub")
        if not user_id:
            logger.warning(f"Google JWT missing 'sub': {payload}")
            return None
        logger.info(f"Google JWT verified successfully for user_id={user_id}")
        return user_id
    except ValueError as e:
        logger.warning(f"Invalid Google JWT: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error verifying Google JWT: {str(e)}")
        return None

# ----------------------
# Generate backend JWT for frontend
# ----------------------
def generate_jwt(user_id):
    secret = os.environ.get("JWT_SECRET", "supersecret")
    payload = {
        "user_id": str(user_id),
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    return token

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
        user_id = None
        if token:
            try:
                secret = os.environ.get("JWT_SECRET", "supersecret")
                decoded = jwt.decode(token, secret, algorithms=["HS256"])
                user_id = decoded.get("user_id")
            except jwt.ExpiredSignatureError:
                return jsonify({"success": False, "error": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"success": False, "error": "Invalid token"}), 401

        if not user_id:
            return jsonify({"success": False, "error": "Authentication required"}), 401

        user = get_user_by_id(user_id)
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 401

        request.user = user
        return f(user_id, *args, **kwargs)

    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(user_id, *args, **kwargs):
        user = get_user_by_id(user_id)
        if not user or user.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        return f(user_id, *args, **kwargs)
    return decorated
