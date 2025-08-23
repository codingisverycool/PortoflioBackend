import os
import logging
import datetime
import jwt

from flask import request, jsonify
from flask_login import login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

from api.database.db import db_query

# --- Logging setup ---
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

# --- JWT Settings ---
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev_secret_key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_DAYS = int(os.getenv("JWT_EXPIRE_DAYS", "7"))
JWT_ISS = os.getenv("BACKEND_JWT_ISS", "your-app-name")
JWT_AUD = os.getenv("BACKEND_JWT_AUD", "your-app-client")


def get_user_by_email(email):
    """Fetch user by email from DB"""
    logger.debug("Fetching user by email: %s", email)
    sql = "SELECT id, email, password FROM users WHERE email = %s"
    result = db_query(sql, (email,), fetchone=True)
    logger.debug("DB result for email %s: %s", email, result)
    return result


def generate_jwt(user_id):
    """Generate JWT token for user"""
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(days=JWT_EXPIRE_DAYS)

    payload = {
        "user_id": str(user_id),
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "iat": now,
        "exp": exp,
    }

    try:
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        logger.debug("Generated JWT for user %s: %s", user_id, token)
        return token
    except Exception as e:
        logger.error("Error generating JWT: %s", str(e), exc_info=True)
        return None


def decode_jwt(token):
    """Decode JWT token"""
    try:
        logger.debug("Attempting to decode JWT: %s", token)
        decoded = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUD,
            issuer=JWT_ISS,
        )
        logger.debug("Decoded JWT payload: %s", decoded)
        return decoded
    except jwt.ExpiredSignatureError:
        logger.warning("JWT expired")
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid JWT: %s", str(e))
    except Exception as e:
        logger.error("Unexpected error decoding JWT: %s", str(e), exc_info=True)
    return None


def token_required(f):
    """Decorator to require JWT token for Flask routes"""
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", None)
        logger.debug("Authorization header: %s", auth_header)

        if not auth_header or not auth_header.startswith("Bearer "):
            logger.warning("Missing or invalid Authorization header")
            return jsonify({"message": "Missing or invalid token"}), 401

        token = auth_header.split(" ")[1]
        decoded = decode_jwt(token)
        if not decoded:
            logger.warning("Token decode failed, rejecting request")
            return jsonify({"message": "Invalid or expired token"}), 401

        logger.debug("JWT successfully validated for user %s", decoded.get("user_id"))
        return f(*args, **kwargs, current_user=decoded)

    return decorated


# Example login endpoint (kept intact)
def login(email, password):
    logger.debug("Login attempt for email: %s", email)
    user = get_user_by_email(email)

    if not user:
        logger.warning("User not found for email: %s", email)
        return None

    if not check_password_hash(user["password"], password):
        logger.warning("Password check failed for email: %s", email)
        return None

    login_user(user)
    token = generate_jwt(user["id"])
    logger.info("User %s logged in successfully", user["id"])
    return token


def logout():
    logger.info("Logging out current user")
    logout_user()

def verify_jwt_token(token: str):
    try:
        decoded = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISS,
            audience=JWT_AUD
        )
        logger.info("✅ JWT decoded successfully: %s", decoded)
        return decoded
    except jwt.ExpiredSignatureError:
        logger.warning("❌ Invalid JWT: Token has expired")
    except jwt.InvalidIssuerError:
        logger.warning("❌ Invalid JWT: Wrong issuer (expected %s)", JWT_ISS)
    except jwt.InvalidAudienceError:
        logger.warning("❌ Invalid JWT: Wrong audience (expected %s)", JWT_AUD)
    except jwt.InvalidSignatureError:
        logger.warning("❌ Invalid JWT: Signature verification failed")
    except Exception as e:
        logger.warning("❌ Invalid JWT: %s", str(e))
    return None