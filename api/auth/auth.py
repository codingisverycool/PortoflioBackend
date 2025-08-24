# api/auth/auth.py

import os
from functools import wraps
from flask import request, jsonify
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from api.database.db import db_query

# --- Google Client ID ---
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
if not GOOGLE_CLIENT_ID:
    raise ValueError("GOOGLE_CLIENT_ID environment variable not set")


def google_jwt_required(f):
    """
    Decorator to protect routes with Google JWT.
    Verifies the token and attaches the user DB record (with UUID) to `request.user`.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"message": "Authorization header missing or invalid"}), 401

        token = auth_header.split(" ")[1]

        try:
            # Verify the token with Google
            id_info = id_token.verify_oauth2_token(
                token,
                google_requests.Request(),
                GOOGLE_CLIENT_ID
            )

            if id_info.get("iss") not in ["accounts.google.com", "https://accounts.google.com"]:
                raise ValueError("Wrong issuer")

            # Extract email from token
            email = id_info.get("email")
            if not email:
                raise ValueError("Email not found in token")

            # Fetch the user from the database using email
            user_record = db_query(
                "SELECT id, email, role, name, meta, created_at, updated_at FROM users WHERE email = %s",
                (email,),
                fetchone=True
            )

            if not user_record:
                return jsonify({"message": "User not found"}), 401

            # Attach user info to request for downstream routes
            request.user = user_record  # user_record contains UUID under "id"
            request.user_info = id_info  # raw Google payload

        except ValueError as e:
            print(f"Token verification failed: {e}")
            return jsonify({"message": "Invalid token"}), 401
        except Exception as e:
            print(f"Unexpected error in token verification: {e}")
            return jsonify({"message": "Authentication failed"}), 500

        return f(*args, **kwargs)

    return decorated_function


# Optional helper to get current user UUID safely
def get_current_user_id():
    """
    Returns the UUID of the currently authenticated user.
    """
    return getattr(request, "user", {}).get("id")
