# api/auth/routes.py
import json
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify
from flask_login import login_user, logout_user

from werkzeug.security import generate_password_hash, check_password_hash

from api.database.db import db_query
from api.auth.auth import generate_jwt, token_required, login_manager

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

auth_bp = Blueprint('auth_bp', __name__)

# Register/login/logout routes (DB-backed). Email sending has been intentionally removed.
@auth_bp.route('/api/register', methods=['POST'])
def register():
    data = request.json or request.form
    email = (data.get('email') or '').strip().lower()
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not email or not password or not confirm_password:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    if password != confirm_password:
        return jsonify({'success': False, 'error': 'Passwords do not match'}), 400
    if len(password) < 8:
        return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400

    existing = db_query("SELECT id FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
    if existing:
        return jsonify({'success': False, 'error': 'Email already registered'}), 400

    encrypted_pass = generate_password_hash(password, method='pbkdf2:sha256')
    try:
        db_query("""
            INSERT INTO users (email, encrypted_pass, verified, meta, created_at, updated_at)
            VALUES (%s, %s, %s, %s::jsonb, NOW(), NOW());
        """, (email, encrypted_pass, False, json.dumps({})), commit=True)
        return jsonify({'success': True, 'message': 'Account created. Please verify email (if enabled).'}), 200
    except Exception as e:
        logger.exception("Failed to create user: %s", e)
        return jsonify({'success': False, 'error': 'Failed to create user'}), 500


@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or request.form
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    logger.debug("Login attempt: %s (pwdlen=%d)", email, len(password))
    user = db_query("SELECT * FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    if not user.get('verified'):
        return jsonify({'success': False, 'error': 'Email not verified'}), 403
    encrypted = user.get('encrypted_pass')
    if not encrypted or not check_password_hash(encrypted, password):
        return jsonify({'success': False, 'error': 'Incorrect password'}), 401

    # login with flask-login (session) for parity, and return JWT for API calls
    try:
        uobj = type('U', (), {})()
        uobj.id = str(user['id'])
        uobj.email = user.get('email')
        login_user(uobj)
    except Exception:
        # session login is optional; JWT will still be returned
        logger.debug("Session login skipped/failed, continuing with JWT")

    try:
        db_query("UPDATE users SET last_login = NOW() WHERE id = %s", (user['id'],), commit=True)
    except Exception:
        logger.exception("Failed to update last_login")
    token = generate_jwt(user['id'])
    return jsonify({'success': True, 'message': 'Login successful', 'token': token})


@auth_bp.route('/api/oauth/login', methods=['POST'])
def oauth_login():
    """
    Lightweight OAuth login endpoint for client-side flows:
      Client posts { email, name, provider } after verifying identity client-side (or via NextAuth).
      This endpoint upserts user and returns an app JWT. Mark user verified True for OAuth.
    """
    try:
        data = request.get_json() or {}
        email = (data.get('email') or '').strip().lower()
        name = data.get('name')
        provider = data.get('provider', 'oauth')

        if not email:
            return jsonify({'success': False, 'error': 'Missing email'}), 400

        existing = db_query("SELECT id, meta FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
        if existing:
            user_id = existing['id']
            meta = existing.get('meta') or {}
            if isinstance(meta, dict):
                meta.update({'last_oauth_provider': provider, 'name': name})
            else:
                meta = {'last_oauth_provider': provider, 'name': name}
            db_query("UPDATE users SET meta = %s::jsonb, updated_at = NOW() WHERE id = %s", (json.dumps(meta), user_id), commit=True)
        else:
            row = db_query("""
                INSERT INTO users (email, encrypted_pass, verified, meta, created_at, updated_at)
                VALUES (%s, %s, %s, %s::jsonb, NOW(), NOW())
                RETURNING id;
            """, (email, None, True, json.dumps({'name': name, 'oauth_provider': provider})), fetchone=True, commit=True)
            user_id = row['id'] if row else None

        if not user_id:
            return jsonify({'success': False, 'error': 'Failed to create/find user'}), 500

        token = generate_jwt(user_id)
        return jsonify({'success': True, 'token': token, 'user': {'id': user_id, 'email': email}})

    except Exception:
        logger.exception("oauth_login error")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@auth_bp.route('/api/auth/nextauth-oauth', methods=['POST'])
def nextauth_oauth():
    """
    Accept server-to-server payload from NextAuth (or any OAuth proxy).
    Body:
      { provider, provider_user_id, email, email_verified, profile, tokens }
    This will upsert/link user and identity and return app JWT.
    """
    data = request.json or {}
    provider = data.get('provider')
    provider_user_id = data.get('provider_user_id')
    email = (data.get('email') or '').strip().lower()
    email_verified = bool(data.get('email_verified', False))
    profile = data.get('profile') or {}
    tokens = data.get('tokens') or {}

    if not provider or not provider_user_id:
        return jsonify({'success': False, 'error': 'Missing provider info'}), 400

    try:
        # 1) find by identity
        row = db_query("""
            SELECT u.* FROM users u
            JOIN user_identities ui ON ui.user_id = u.id
            WHERE ui.provider = %s AND ui.provider_user_id = %s
            LIMIT 1
        """, (provider, provider_user_id), fetchone=True)

        if row:
            user = dict(row)
        else:
            user = None
            if email:
                row = db_query("SELECT * FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
                if row:
                    user = dict(row)

            if user:
                # link provider identity if missing
                try:
                    db_query("""
                        INSERT INTO user_identities (user_id, provider, provider_user_id, provider_profile, tokens)
                        VALUES (%s,%s,%s,%s::jsonb,%s::jsonb)
                        ON CONFLICT (provider, provider_user_id) DO NOTHING
                    """, (user['id'], provider, provider_user_id, json.dumps(profile), json.dumps(tokens)), commit=True)
                    if email_verified and not user.get('verified'):
                        db_query("UPDATE users SET verified = TRUE, updated_at = NOW() WHERE id = %s", (user['id'],), commit=True)
                except Exception:
                    logger.exception("Error linking identity to existing user")
            else:
                # create new user and identity
                meta = {'oauth': {provider: {'sub': provider_user_id, 'profile': profile, 'created_at': datetime.utcnow().isoformat()}}}
                db_query("""
                    INSERT INTO users (email, encrypted_pass, verified, meta, created_at, updated_at)
                    VALUES (%s,%s,%s,%s::jsonb,NOW(),NOW())
                """, (email, None, email_verified, json.dumps(meta)), commit=True)
                user = db_query("SELECT * FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
                try:
                    db_query("""
                        INSERT INTO user_identities (user_id, provider, provider_user_id, provider_profile, tokens)
                        VALUES (%s,%s,%s,%s::jsonb,%s::jsonb)
                    """, (user['id'], provider, provider_user_id, json.dumps(profile), json.dumps(tokens)), commit=True)
                except Exception:
                    logger.exception("Error inserting user identity for new user")

        token = generate_jwt(user['id'])
        return jsonify({'success': True, 'token': token, 'user_id': user['id']})
    except Exception as e:
        logger.exception("nextauth_oauth error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to process OAuth login'}), 500


@auth_bp.route('/api/logout', methods=['POST'])
@token_required
def logout(user_id):
    # For token-based auth nothing to do server-side; for session-based use logout_user()
    try:
        logout_user()
    except Exception:
        pass
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200
