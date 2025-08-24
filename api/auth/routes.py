# api/routes/auth_routes.py

import os
import json
import logging
from flask import Blueprint, request, jsonify, make_response

from api.database.db import db_query
from api.auth.auth import google_jwt_required

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

auth_bp = Blueprint("auth_bp", __name__)


def cors_response(data=None, status=200):
    """Return JSON response with CORS headers attached."""
    response = make_response(data or "")
    response.status_code = status
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE")
    return response


@auth_bp.route("/api/oauth/login", methods=["POST", "OPTIONS"])
@google_jwt_required
def oauth_login():
    if request.method == "OPTIONS":
        return cors_response()

    try:
        # Extract user info from verified Google ID token
        id_info = request.user_info
        email = id_info.get("email")
        name = id_info.get("name") or "User"

        if not email:
            return cors_response(jsonify({"success": False, "error": "Email required"}), 400)

        # Check if user exists by email
        row = db_query(
            "SELECT id, email, role, verified, created_at FROM users WHERE email = %s LIMIT 1",
            (email,),
            fetchone=True
        )

        if row:
            user = dict(row)
        else:
            # Create new user with UUID as primary key
            row = db_query(
                """
                INSERT INTO users (email, role, created_at)
                VALUES (%s, 'client', NOW())
                RETURNING id, email, role, verified, created_at
                """,
                (email,),
                fetchone=True,
                commit=True
            )
            user = dict(row)

        return cors_response(jsonify({"success": True, "user": user}), 200)

    except Exception as e:
        logger.exception("OAuth login error: %s", e)
        return cors_response(jsonify({"success": False, "error": str(e)}), 500)
