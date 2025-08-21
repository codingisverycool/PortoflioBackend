# api/auth/auth.py
import os
import logging
import datetime
import jwt
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
# Google ID Token verification (for login only)
# ----------------------
def verify_google_jwt(token):
    """
    Verifies a Google ID token using google-auth library.
    Returns the payload (dict) if valid, else None.
    """
    try:
        CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
        payload = id_token.verify_oauth2_token(
            token, google_requests.Request(), CLIENT_ID
        )
        logger.info(f"Google JWT verified successfully for {payload.get('email')}")
        return payload
    except ValueError as e:
        logger.warning(f"Invalid Google JWT: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error verifying Google JWT: {str(e)}")
        return None

# ----------------------
# Backend JWT helpers
# ----------------------
def generate_jwt(user_id, email):
    """
    Create backend JWT for authenticated users.
    """
    try:
        payload = {
            "user_id": user_id,
            "email": email,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        token = jwt.encode(payload, os.environ.get("JWT_SECRET_KEY"), algorithm="HS256")
        return token
    except Exception as e:
        logger.error(f"Error generating JWT: {str(e)}")
        return None

def decode_jwt(token):
    try:
        return jwt.decode(token, os.environ.get("JWT_SECRET_KEY"), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        logger.warning("JWT expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT: {str(e)}")
        return None

# ----------------------
# Decorators
# ----------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "OPTIONS":
            resp = make_response()
            origin = request.headers.get("Origin", "*")
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Max-Age"] = "86400"
            return resp

        # Get token from header
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"success": False, "error": "Authentication required"}), 401

        token = auth.split(" ", 1)[1].strip()
        if not token:
            return jsonify({"success": False, "error": "Authentication required"}), 401

        # Verify backend JWT
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"success": False, "error": "Invalid or expired token"}), 401

        user = get_user_by_id(payload.get("user_id"))
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 401

        request.user = user
        return f(user["id"], *args, **kwargs)

    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(user_id, *args, **kwargs):
        user = get_user_by_id(user_id)
        if not user or user.get("role") != "admin":
            return jsonify({"success": False, "error": "Admin access required"}), 403
        return f(user_id, *args, **kwargs)
    return decorated
