# api/auth/routes.py
import json
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, make_response
from flask_login import login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

from api.database.db import db_query
from api.auth.auth import generate_jwt, token_required

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

auth_bp = Blueprint('auth_bp', __name__)

# --- Helper to add CORS headers ---
def cors_response(resp):
    origin = request.headers.get('Origin', '*')
    resp.headers['Access-Control-Allow-Origin'] = origin
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return resp

# --- Registration ---
@auth_bp.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return cors_response(make_response())

    data = request.json or request.form
    email = (data.get('email') or '').strip().lower()
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not email or not password or not confirm_password:
        return cors_response(jsonify({'success': False, 'error': 'Missing required fields'})), 400
    if password != confirm_password:
        return cors_response(jsonify({'success': False, 'error': 'Passwords do not match'})), 400
    if len(password) < 8:
        return cors_response(jsonify({'success': False, 'error': 'Password must be at least 8 characters'})), 400

    existing = db_query("SELECT id FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
    if existing:
        return cors_response(jsonify({'success': False, 'error': 'Email already registered'})), 400

    encrypted_pass = generate_password_hash(password, method='pbkdf2:sha256')
    try:
        db_query("""
            INSERT INTO users (email, encrypted_pass, verified, meta, created_at, updated_at)
            VALUES (%s, %s, %s, %s::jsonb, NOW(), NOW());
        """, (email, encrypted_pass, False, json.dumps({})), commit=True)
        return cors_response(jsonify({'success': True, 'message': 'Account created. Please verify email if enabled.'})), 200
    except Exception as e:
        logger.exception("Failed to create user: %s", e)
        return cors_response(jsonify({'success': False, 'error': 'Failed to create user'})), 500

# --- Login ---
@auth_bp.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return cors_response(make_response())

    data = request.get_json() or request.form
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    user = db_query("SELECT * FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
    if not user:
        return cors_response(jsonify({'success': False, 'error': 'User not found'})), 404
    if not user.get('verified'):
        return cors_response(jsonify({'success': False, 'error': 'Email not verified'})), 403

    encrypted = user.get('encrypted_pass')
    if encrypted:
        if not check_password_hash(encrypted, password):
            return cors_response(jsonify({'success': False, 'error': 'Incorrect password'})), 401
    else:
        return cors_response(jsonify({'success': False, 'error': 'Use OAuth login'})), 401

    # Session login (optional)
    try:
        uobj = type('U', (), {})()
        uobj.id = str(user['id'])
        uobj.email = user.get('email')
        login_user(uobj)
    except Exception:
        logger.debug("Session login skipped/failed, continuing with JWT")

    try:
        db_query("UPDATE users SET last_login = NOW() WHERE id = %s", (user['id'],), commit=True)
    except Exception:
        logger.exception("Failed to update last_login")
    
    token = generate_jwt(user['id'])
    return cors_response(jsonify({'success': True, 'message': 'Login successful', 'token': token, 'user': {'id': user['id'], 'email': email}}))

# --- OAuth login ---
@auth_bp.route('/api/oauth/login', methods=['POST', 'OPTIONS'])
def oauth_login():
    if request.method == 'OPTIONS':
        return cors_response(make_response())
    try:
        data = request.get_json() or {}
        email = (data.get('email') or '').strip().lower()
        name = data.get('name')
        provider = data.get('provider', 'oauth')

        if not email:
            return cors_response(jsonify({'success': False, 'error': 'Missing email'})), 400

        existing = db_query("SELECT id, meta FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
        if existing:
            user_id = existing['id']
            meta = existing.get('meta') or {}
            meta = meta if isinstance(meta, dict) else {}
            meta.update({'last_oauth_provider': provider, 'name': name})
            db_query("UPDATE users SET meta = %s::jsonb, updated_at = NOW() WHERE id = %s", (json.dumps(meta), user_id), commit=True)
        else:
            row = db_query("""
                INSERT INTO users (email, encrypted_pass, verified, meta, created_at, updated_at)
                VALUES (%s, %s, %s, %s::jsonb, NOW(), NOW())
                RETURNING id;
            """, (email, None, True, json.dumps({'name': name, 'oauth_provider': provider})), fetchone=True, commit=True)
            user_id = row['id'] if row else None

        if not user_id:
            return cors_response(jsonify({'success': False, 'error': 'Failed to create/find user'})), 500

        token = generate_jwt(user_id)
        return cors_response(jsonify({'success': True, 'token': token, 'user': {'id': user_id, 'email': email}}))
    except Exception:
        logger.exception("oauth_login error")
        return cors_response(jsonify({'success': False, 'error': 'Internal server error'})), 500

# --- Logout ---
@auth_bp.route('/api/logout', methods=['POST', 'OPTIONS'])
@token_required
def logout(user_id):
    if request.method == 'OPTIONS':
        return cors_response(make_response())
    try:
        logout_user()
    except Exception:
        pass
    return cors_response(jsonify({'success': True, 'message': 'Logged out successfully'})), 200
