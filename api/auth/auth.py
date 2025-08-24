# api/auth/auth.py

import os
from functools import wraps
from flask import request, jsonify
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# --- Google Client ID ---
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
if not GOOGLE_CLIENT_ID:
    raise ValueError("GOOGLE_CLIENT_ID environment variable not set")


# --- Decorator for verifying Google ID tokens ---
def google_jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"message": "Authorization header missing or invalid"}), 401

        token = auth_header.split(" ")[1]
        try:
            # Verify the token using Google's library
            id_info = id_token.verify_oauth2_token(
                token,
                google_requests.Request(),
                GOOGLE_CLIENT_ID
            )

            # Extra safety check for issuer
            if id_info["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
                raise ValueError("Wrong issuer.")

            # Attach user info to the request object for downstream use
            request.user_info = id_info

        except ValueError as e:
            print(f"Token verification failed: {e}")
            return jsonify({"message": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated_function
