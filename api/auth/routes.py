import os
import json
import logging
from flask import Blueprint, request, jsonify, make_response

from werkzeug.security import generate_password_hash, check_password_hash

from api.database.db import db_query
from api.auth.auth import get_user_by_email, generate_jwt, token_required, cors_response

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

auth_bp = Blueprint("auth_bp", __name__)

# ----------------------
# Registration (optional for Google-only)
# ----------------------
@auth_bp.route("/api/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        return cors_response(make_response())

    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password")
    confirm_password = data.get("confirm_password")

    if not email or not password or not confirm_password:
        return cors_response(jsonify({"success": False, "error": "Missing required fields"})), 400
    if password != confirm_password:
        return cors_response(jsonify({"success": False, "error": "Passwords do not match"})), 400
    if len(password) < 8:
        return cors_response(jsonify({"success": False, "error": "Password must be at least 8 characters"})), 400

    existing = db_query("SELECT id FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
    if existing:
        return cors_response(jsonify({"success": False, "error": "Email already registered"})), 400

    encrypted_pass = generate_password_hash(password, method="pbkdf2:sha256")
    try:
        db_query(
            """
            INSERT INTO users (email, encrypted_pass, verified, meta, created_at, updated_at)
            VALUES (%s, %s, %s, %s::jsonb, NOW(), NOW())
            """,
            (email, encrypted_pass, False, json.dumps({})),
            commit=True,
        )
        return cors_response(jsonify({"success": True, "message": "Account created"})), 200
    except Exception as e:
        logger.exception("Failed to create user: %s", e)
        return cors_response(jsonify({"success": False, "error": "Failed to create user"})), 500


# ----------------------
# Classic login (optional if only Google)
# ----------------------
@auth_bp.route("/api/login", methods=["POST", "OPTIONS"])
def classic_login():
    if request.method == "OPTIONS":
        return cors_response(make_response())

    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = db_query("SELECT * FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
    if not user:
        return cors_response(jsonify({"success": False, "error": "User not found"})), 404

    encrypted = user.get("encrypted_pass")
    if not encrypted or not check_password_hash(encrypted, password):
        return cors_response(jsonify({"success": False, "error": "Incorrect password"})), 401

    # Generate backend JWT
    token = generate_jwt(user["id"], user["email"])

    return cors_response(jsonify({"success": True, "token": token, "user": {"id": user["id"], "email": user["email"]}}))


# ----------------------
# OAuth login (Google via NextAuth)
# ----------------------
@auth_bp.route("/api/oauth/login", methods=["POST", "OPTIONS"])
def oauth_login():
    if request.method == "OPTIONS":
        return cors_response(make_response())

    try:
        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()
        name = data.get("name") or "User"

        if not email:
            return cors_response(jsonify({"success": False, "error": "Email required"})), 400

        user = get_user_by_email(email)
        if not user:
            # Create new user
            row = db_query(
                """
                INSERT INTO users (email, name, created_at, role)
                VALUES (%s, %s, NOW(), 'user')
                RETURNING id, email, name, role
                """,
                (email, name),
                fetchone=True,
                commit=True,
            )
            user = dict(row)

        token = generate_jwt(user["id"], user["email"])

        return cors_response(jsonify({"success": True, "token": token, "user": user}))

    except Exception as e:
        logger.exception("OAuth login error: %s", e)
        return cors_response(jsonify({"success": False, "error": str(e)})), 500


# ----------------------
# Logout
# ----------------------
@auth_bp.route("/api/logout", methods=["POST", "OPTIONS"])
@token_required
def logout(user_id):
    if request.method == "OPTIONS":
        return cors_response(make_response())

    # No server session needed, just instruct frontend to remove token
    resp = make_response(jsonify({"success": True, "message": "Logged out successfully"}))
    resp.set_cookie("access_token", "", expires=0, httponly=True, secure=True, samesite="None", path="/")
    return cors_response(resp), 200
