import os
import logging
import datetime
import jwt
from functools import wraps
from flask import request, jsonify, make_response
from api.database.db import db_query

# ----------------------
# Logging
# ----------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    )
    logger.addHandler(handler)

# ----------------------
# User helpers
# ----------------------
def get_user_by_email(email):
    if not email or not isinstance(email, str):
        return None
    try:
        email = email.strip().lower()
        row = db_query("SELECT * FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching user by email {email}: {e}")
        return None

def get_user_by_id(user_id):
    if not user_id:
        return None
    try:
        row = db_query("SELECT * FROM users WHERE id = %s LIMIT 1", (user_id,), fetchone=True)
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching user by ID {user_id}: {e}")
        return None

# ----------------------
# JWT helpers
# ----------------------
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "supersecret")
JWT_ALGO = "HS256"

def generate_jwt(user_id, email, expires_in=7*24*3600):
    """Generate a backend JWT for Flask APIs."""
    payload = {
        "user_id": str(user_id),
        "email": email,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)

def verify_jwt(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        logger.warning("JWT expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid JWT")
        return None

# ----------------------
# Token retrieval
# ----------------------
def get_token_from_request():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return None

# ----------------------
# CORS helper
# ----------------------
def cors_response(resp=None):
    if resp is None:
        resp = make_response()
    origin = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return resp

# ----------------------
# Decorators
# ----------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "OPTIONS":
            return cors_response()

        token = get_token_from_request()
        if not token:
            return jsonify({"success": False, "error": "Authentication required"}), 401

        payload = verify_jwt(token)
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
