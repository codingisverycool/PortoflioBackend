# index.py -- DB-backed unified backend (Flask + Postgres + JWT)
from flask import Flask, request, url_for, jsonify, make_response
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import yfinance as yf
import json
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import secrets
from collections import defaultdict
import pandas as pd
import logging
from functools import wraps
import jwt

# DB imports
import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool

# ---------- App & config ----------
app = Flask(__name__)
CORS(app, supports_credentials=True)

# secrets from env
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-default-secret-key')
DATABASE_URL = os.environ.get('DATABASE_URL')  # must be set for DB-backed usage

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Email configuration (move real secrets to env in production)
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    MAIL_SERVER='smtp.sendgrid.net',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME='apikey',
    MAIL_PASSWORD=os.environ.get('SENDGRID_API_KEY', ''),  # << use env
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@example.com')
)
mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---------- DB pool & helpers ----------
_pool = None
def get_pool():
    global _pool
    if _pool is None:
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL not set. Set it in environment.")
        _pool = SimpleConnectionPool(1, 10, dsn=DATABASE_URL)
    return _pool

def get_conn():
    return get_pool().getconn()

def release_conn(conn):
    try:
        if conn:
            get_pool().putconn(conn)
    except Exception:
        # If pool already closed or broken, just ignore here but log
        logger.exception("Error releasing DB connection")

def db_query(sql, params=None, fetchone=False, fetchall=False, commit=False):
    """
    Generic DB helper. Rolls back on exception and always releases connection back to pool.
    For multi-statement transactional work use get_conn() and a manual cursor.
    """
    conn = None
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params or ())
            result = None
            if fetchone:
                result = cur.fetchone()
            elif fetchall:
                result = cur.fetchall()
            if commit:
                conn.commit()
            return result
    except Exception:
        # Ensure transaction is rolled back so connection is clean for pool reuse
        try:
            if conn:
                conn.rollback()
        except Exception:
            logger.exception("Failed to rollback connection after error")
        logger.exception("db_query failed for SQL: %s params: %s", sql, params)
        raise
    finally:
        release_conn(conn)

# ---------- Ensure DB schema ----------
def ensure_tables():
    """Create minimal required tables if they don't exist."""
    if not DATABASE_URL:
        logger.warning("DATABASE_URL not set; skipping table creation.")
        return

    sql = """
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

    CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        encrypted_pass TEXT,
        verified BOOLEAN DEFAULT FALSE,
        role VARCHAR(50) DEFAULT 'client',
        meta JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        last_login TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS user_risk_profiles (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        profile_json JSONB NOT NULL,
        total_score INTEGER,
        risk_bracket VARCHAR(100),
        created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(10) NOT NULL CHECK (type IN ('Buy','Sell')),
        stock VARCHAR(32) NOT NULL,
        quantity INTEGER NOT NULL CHECK (quantity > 0),
        price NUMERIC(20,4) NOT NULL CHECK (price >= 0),
        date DATE NOT NULL,
        notes TEXT,
        source VARCHAR(50),
        created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_transactions_user_stock ON transactions(user_id, stock);
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            conn.commit()
    finally:
        release_conn(conn)

# initialize tables
try:
    if DATABASE_URL:
        ensure_tables()
    else:
        logger.warning("DATABASE_URL not set; DB-backed features disabled.")
except Exception as e:
    logger.exception("Error ensuring tables: %s", e)

RISK_QUESTIONNAIRE = {
    "questions": [
        # ... unchanged ...
    ],
    "risk_brackets": [
        {"name": "Defensive", "min": 0, "max": 129},
        {"name": "Moderate", "min": 130, "max": 259},
        {"name": "Aggressive", "min": 260, "max": 359},
        {"name": "Very Aggressive", "min": 360, "max": 400}
    ]
}

# ---------- User Class & user helpers ----------
class User(UserMixin):
    def __init__(self, user_id, email=None):
        # user_id is the DB UUID (string)
        self.id = str(user_id)
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    """Flask-Login loader (user_id is UUID string)."""
    try:
        row = db_query("SELECT id, email, verified FROM users WHERE id = %s", (user_id,), fetchone=True)
        if not row:
            return None
        return User(row['id'], row.get('email'))
    except Exception:
        return None

def get_user_by_email(email):
    if not DATABASE_URL:
        return None
    try:
        row = db_query("SELECT * FROM users WHERE email = %s", (email,), fetchone=True)
        return dict(row) if row else None
    except Exception as e:
        logger.exception("get_user_by_email error: %s", e)
        return None

def get_user_by_id(user_id):
    if not DATABASE_URL:
        return None
    try:
        row = db_query("SELECT * FROM users WHERE id = %s", (user_id,), fetchone=True)
        return dict(row) if row else None
    except Exception as e:
        logger.exception("get_user_by_id error: %s", e)
        return None

def load_users():  # compatibility shim if some code calls it
    """Return dict of users (email -> {password, verified, meta})"""
    if not DATABASE_URL:
        if os.path.exists('users.json'):
            with open('users.json') as f:
                return json.load(f)
        return {}
    try:
        rows = db_query("SELECT email, encrypted_pass, verified, meta FROM users", fetchall=True)
        users = {}
        for r in rows or []:
            users[r['email']] = {
                'password': r.get('encrypted_pass'),
                'verified': r.get('verified', False),
                'meta': r.get('meta', {})
            }
        return users
    except Exception as e:
        logger.exception("load_users error: %s", e)
        return {}

def save_users(users):
    """Upsert users dict into DB (compatibility layer)."""
    if not DATABASE_URL:
        with open('users.json', 'w') as f:
            json.dump(users, f)
        return
    try:
        for email, u in users.items():
            encrypted_pass = u.get('password') or u.get('encrypted_pass')
            verified = u.get('verified', False)
            meta = u.get('meta', {})
            db_query("""
                INSERT INTO users (email, encrypted_pass, verified, meta, created_at, updated_at)
                VALUES (%s, %s, %s, %s::jsonb, NOW(), NOW())
                ON CONFLICT (email) DO UPDATE
                  SET encrypted_pass = EXCLUDED.encrypted_pass,
                      verified = EXCLUDED.verified,
                      meta = EXCLUDED.meta,
                      updated_at = NOW();
            """, (email, encrypted_pass, verified, json.dumps(meta)), commit=True)
    except Exception as e:
        logger.exception("save_users error: %s", e)
        raise

# ---------- JWT helpers ----------
def generate_jwt(user_id):
    payload = {
        "user_id": str(user_id),
        "exp": datetime.utcnow() + timedelta(days=1),
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
    # pyjwt may return bytes in some versions
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def verify_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload.get("user_id")
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# ---------- token_required decorator (supports JWT + session fallback) ----------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Handle OPTIONS preflight
        if request.method == 'OPTIONS':
            response = make_response()
            origin = request.headers.get('Origin', '*')
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Methods'] = "GET,POST,OPTIONS"
            response.headers['Access-Control-Allow-Headers'] = "Content-Type, Authorization"
            response.headers['Access-Control-Allow-Credentials'] = "true"
            return response

        auth_header = request.headers.get('Authorization', '')
        user_id = None
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1].strip()
            user_id = verify_jwt(token)

        # fallback to Flask-Login session if token is missing/invalid
        if not user_id:
            try:
                if current_user and current_user.is_authenticated:
                    user_id = current_user.id
            except Exception:
                user_id = None

        if not user_id:
            response = jsonify({'success': False, 'error': 'Token is missing or user not authenticated!'})
            response.status_code = 401
            origin = request.headers.get('Origin', '*')
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response

        # verify user exists in DB
        u = get_user_by_id(user_id)
        if not u:
            response = jsonify({'success': False, 'error': 'Invalid or expired token!'})
            response.status_code = 401
            origin = request.headers.get('Origin', '*')
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response

        # Pass user_id to wrapped route
        return f(user_id, *args, **kwargs)
    return decorated

# ---------- Risk endpoints ----------
@app.route('/api/risk/questionnaire', methods=['GET'])
@token_required
def get_risk_questionnaire(user_id):
    return jsonify({"success": True, "questionnaire": RISK_QUESTIONNAIRE})

@app.route('/api/risk/submit', methods=['POST', 'OPTIONS'])
@token_required
def submit_risk(user_id):
    if request.method == 'OPTIONS':
        response = make_response()
        origin = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = "POST, OPTIONS"
        response.headers['Access-Control-Allow-Headers'] = "Content-Type, Authorization"
        response.headers['Access-Control-Allow-Credentials'] = "true"
        return response

    try:
        data = request.get_json() or request.form
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        answers = {
            "q1": (data.get("purposeOfInvesting") or "").upper(),
            "q2": (data.get("lifeStage") or "").upper(),
            "q3": (data.get("expectedReturns") or "").upper(),
            "q4": (data.get("derivativeProducts") or "").upper(),
            "q5": (data.get("investmentHorizon") or "").upper(),
            "q6": (data.get("marketDownturnReaction") or "").upper(),
            "q7": (data.get("incomeStability") or "").upper(),
            "q8": (data.get("emergencySavings") or "").upper()
        }

        # Calculate total_score
        total_score = 0
        for q in RISK_QUESTIONNAIRE["questions"]:
            ans = answers.get(q["id"])
            if ans and ans in q["options"]:
                total_score += q["options"][ans]["score"]

        # Determine bracket
        risk_bracket = "Undetermined"
        for bracket in RISK_QUESTIONNAIRE["risk_brackets"]:
            if bracket["min"] <= total_score <= bracket["max"]:
                risk_bracket = bracket["name"]
                break

        profile_data = {
            "user_id": user_id,
            "submitted_at": datetime.utcnow().isoformat(),
            "client_details": {
                "name": data.get("applicantName"),
                "address": data.get("applicantAddress"),
                "advisor_name": data.get("advisorName"),
                "advisor_designation": data.get("advisorDesignation"),
                "assessment_date": data.get("assessmentDate"),
                "assessment_place": data.get("assessmentPlace")
            },
            "signature": data.get("applicantSignature"),
            "total_score": total_score,
            "risk_bracket": risk_bracket,
            "interested_investments": data.get("interestedInvestments", []),
            "answers": answers
        }

        db_query("""
            INSERT INTO user_risk_profiles (user_id, profile_json, total_score, risk_bracket, created_at)
            VALUES (%s, %s::jsonb, %s, %s, NOW());
        """, (user_id, json.dumps(profile_data), total_score, risk_bracket), commit=True)

        return jsonify({"success": True, "total_score": total_score, "risk_bracket": risk_bracket})

    except KeyError as e:
        logger.error("Missing field: %s", e)
        return jsonify({"success": False, "error": f"Missing required field: {str(e)}"}), 400
    except Exception as e:
        logger.exception("Risk assessment submission error: %s", e)
        return jsonify({"success": False, "error": "Failed to process risk assessment"}), 500

@app.route('/api/risk/check', methods=['GET'])
@token_required
def check_risk_assessment(user_id):
    try:
        row = db_query("""
            SELECT profile_json
            FROM user_risk_profiles
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1;
        """, (user_id,), fetchone=True)
        if row:
            return jsonify({"success": True, "completed": True, "latest_assessment": row['profile_json']})
        else:
            return jsonify({"success": True, "completed": False})
    except Exception as e:
        logger.exception("check_risk_assessment error: %s", e)
        return jsonify({"success": False, "error": "Failed to fetch assessment"}), 500

# ---------- Market / holdings logic ----------
def get_stock_info(ticker):
    try:
        stock = yf.Ticker(ticker)
        info = stock.info or {}
        hist = stock.history(period="1d")
        price = float(hist['Close'].iloc[-1]) if not hist.empty else 0.0
        # Provide a consistent set of keys used elsewhere
        return {
            'price': price,
            'currency': info.get('currency', 'N/A'),
            'exchange': info.get('exchange', 'N/A'),
            'industry': info.get('industry', 'N/A'),
            'sector': info.get('sector', 'N/A'),
            '52w_high': info.get('fiftyTwoWeekHigh', info.get('52WeekHigh')),
            '52w_low': info.get('fiftyTwoWeekLow', info.get('52WeekLow')),
            'shortName': info.get('shortName'),
            'longName': info.get('longName'),
            'name': info.get('shortName') or info.get('longName'),
            'marketCap': info.get('marketCap'),
            'trailingPE': info.get('trailingPE'),
            'forwardPE': info.get('forwardPE'),
            'pegRatio': info.get('pegRatio'),
            'priceToSalesTrailing12Months': info.get('priceToSalesTrailing12Months'),
            'priceToBook': info.get('priceToBook'),
            'enterpriseToRevenue': info.get('enterpriseToRevenue'),
            'enterpriseToEbitda': info.get('enterpriseToEbitda'),
            'profitMargins': info.get('profitMargins'),
            'returnOnAssets': info.get('returnOnAssets'),
            'returnOnEquity': info.get('returnOnEquity'),
            'totalRevenue': info.get('totalRevenue'),
            'netIncomeToCommon': info.get('netIncomeToCommon'),
            'trailingEps': info.get('trailingEps'),
            'totalCash': info.get('totalCash'),
            'debtToEquity': info.get('debtToEquity'),
            'freeCashflow': info.get('freeCashflow')
        }
    except Exception as e:
        logger.exception("Error fetching data for %s: %s", ticker, e)
        return None

def get_market_data():
    symbols = {'nasdaq': '^IXIC', 'sp500': '^GSPC', 'dow': '^DJI'}
    market_data = {}
    for name, symbol in symbols.items():
        try:
            stock = yf.Ticker(symbol)
            hist = stock.history(period='5d')
            if len(hist) < 2:
                market_data[name] = {'price': 0, 'change': 0, 'change_pct': 0}
                continue
            current = float(hist['Close'].iloc[-1])
            prev = float(hist['Close'].iloc[-2])
            change = current - prev
            change_pct = (change / prev) * 100 if prev else 0
            market_data[name] = {'price': current, 'change': change, 'change_pct': change_pct / 100}
        except Exception as e:
            logger.debug("Error fetching market data for %s: %s", name, e)
            market_data[name] = {'price': 0, 'change': 0, 'change_pct': 0}
    for key in ['nasdaq', 'sp500', 'dow']:
        if key not in market_data:
            market_data[key] = {'price': 0, 'change': 0, 'change_pct': 0}
    return market_data

def calculate_portfolio_irr(transactions):
    cash_flows = []
    dates = []
    for tx in transactions:
        amount = tx['quantity'] * tx['price']
        if tx['type'] == 'Buy':
            amount = -amount
        cash_flows.append(amount)
        # Expecting date strings 'YYYY-MM-DD'
        try:
            dates.append(datetime.strptime(tx['date'], '%Y-%m-%d'))
        except Exception:
            pass
    if not cash_flows:
        return 0
    try:
        total_investment = sum(cf for cf in cash_flows if cf < 0)
        total_return = sum(cf for cf in cash_flows if cf > 0)
        # days_held must be at least 1 to avoid division by zero
        if dates:
            days_held = max(1, (max(dates) - min(dates)).days)
        else:
            days_held = 1
        if total_investment == 0:
            return 0
        base = total_return / abs(total_investment)
        if base <= 0:
            # negative or zero total return: approximate annualized loss/return
            return (base - 1) * 100
        annualized_return = ((base) ** (365.0 / days_held) - 1) * 100
        return annualized_return
    except Exception:
        logger.exception("Error calculating IRR")
        return 0

def calculate_realized_and_initial_investment(transactions):
    lots = {}
    realized_gains = {}
    initial_investment = {}
    for tx in sorted(transactions, key=lambda x: x['date']):
        stock = tx['stock'].upper()
        qty = int(tx['quantity'])
        price = float(tx['price'])
        type_ = tx['type']
        lots.setdefault(stock, [])
        realized_gains.setdefault(stock, 0.0)
        initial_investment.setdefault(stock, 0.0)
        if type_ == 'Buy':
            lots[stock].append({'quantity': qty, 'price': price})
            initial_investment[stock] += qty * price
        elif type_ == 'Sell':
            sell_qty = qty
            sell_proceeds = sell_qty * price
            cost_removed = 0.0
            if not lots[stock]:
                raise ValueError(f"No lots available to sell for {stock}")
            while sell_qty > 0 and lots[stock]:
                lot = lots[stock][0]
                lot_qty = lot['quantity']
                if lot_qty <= sell_qty:
                    cost_removed += lot_qty * lot['price']
                    sell_qty -= lot_qty
                    lots[stock].pop(0)
                else:
                    cost_removed += sell_qty * lot['price']
                    lot['quantity'] -= sell_qty
                    sell_qty = 0
            if sell_qty > 0:
                raise ValueError(f"Trying to sell more shares ({qty}) than held for {stock}")
            realized_gains[stock] += sell_proceeds - cost_removed
    remaining_qty = {}
    remaining_cost_basis = {}
    for stock, stock_lots in lots.items():
        qty = sum(l['quantity'] for l in stock_lots)
        cost = sum(l['quantity'] * l['price'] for l in stock_lots)
        remaining_qty[stock] = qty
        remaining_cost_basis[stock] = cost
    return realized_gains, initial_investment, remaining_cost_basis, remaining_qty

def compute_holdings_from_transactions(transactions):
    holdings = {}
    lots = {}
    realized_gains = {}
    for tx in sorted(transactions, key=lambda x: x['date']):
        stock = tx['stock'].upper()
        quantity = int(tx['quantity'])
        price = float(tx['price'])
        date = tx['date']
        type_ = tx['type']
        if stock not in holdings:
            holdings[stock] = {'stock': stock, 'quantity': 0, 'total_cost': 0.0, 'first_buy_date': date}
            lots[stock] = []
            realized_gains[stock] = 0.0
        if type_ == 'Buy':
            lots[stock].append({'quantity': quantity, 'price': price})
            holdings[stock]['quantity'] += quantity
            holdings[stock]['total_cost'] += quantity * price
            holdings[stock]['first_buy_date'] = min(holdings[stock]['first_buy_date'], date)
        elif type_ == 'Sell':
            if holdings[stock]['quantity'] < quantity:
                # Skip invalid sells (front-end should prevent these)
                continue
            sell_quantity = quantity
            sell_total = 0.0
            cost_removed = 0.0
            while sell_quantity > 0 and lots[stock]:
                lot = lots[stock][0]
                lot_qty = lot['quantity']
                if sell_quantity >= lot_qty:
                    sell_total += lot_qty * price
                    cost_removed += lot_qty * lot['price']
                    sell_quantity -= lot_qty
                    lots[stock].pop(0)
                else:
                    sell_total += sell_quantity * price
                    cost_removed += sell_quantity * lot['price']
                    lot['quantity'] -= sell_quantity
                    sell_quantity = 0
            realized_gains[stock] += sell_total - cost_removed
            holdings[stock]['quantity'] -= quantity
            holdings[stock]['total_cost'] -= cost_removed
            if holdings[stock]['quantity'] <= 0:
                del holdings[stock]
    for stock in list(holdings.keys()):
        remaining_cost = holdings[stock]['total_cost']
        qty = holdings[stock]['quantity']
        avg_cost = remaining_cost / qty if qty > 0 else 0.0
        holdings[stock]['avg_cost'] = avg_cost
        holdings[stock]['realized_gain'] = realized_gains.get(stock, 0.0)
    return holdings

# ---------- Auth routes ----------
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or request.form
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    logger.debug("Login attempt: %s (pwdlen=%d)", email, len(password))
    user = get_user_by_email(email)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    if not user.get('verified'):
        return jsonify({'success': False, 'error': 'Email not verified'}), 403
    encrypted = user.get('encrypted_pass')
    if not encrypted or not check_password_hash(encrypted, password):
        return jsonify({'success': False, 'error': 'Incorrect password'}), 401
    # login with flask-login using DB UUID
    login_user(User(user['id'], user['email']))
    try:
        db_query("UPDATE users SET last_login = NOW() WHERE id = %s", (user['id'],), commit=True)
    except Exception:
        logger.exception("Failed to update last_login")
    token = generate_jwt(user['id'])
    return jsonify({'success': True, 'message': 'Login successful', 'token': token})

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({'success': False, 'error': 'Unauthorized'}), 401

@app.route('/api/register', methods=['POST'])
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
    if get_user_by_email(email):
        return jsonify({'success': False, 'error': 'Email already registered'}), 400
    verification_token = secrets.token_urlsafe(32)
    created_at_iso = datetime.utcnow().isoformat()
    encrypted_pass = generate_password_hash(password, method='pbkdf2:sha256')
    meta = {"verification_token": verification_token, "created_at": created_at_iso}
    try:
        db_query("""
            INSERT INTO users (email, encrypted_pass, verified, meta, created_at, updated_at)
            VALUES (%s, %s, %s, %s::jsonb, NOW(), NOW());
        """, (email, encrypted_pass, False, json.dumps(meta)), commit=True)
    except Exception as e:
        logger.exception("Failed to create user: %s", e)
        return jsonify({'success': False, 'error': 'Failed to create user'}), 500
    # send verification email
    try:
        verification_link = url_for('verify_email', token=verification_token, _external=True)
        msg = Message("Verify Your Email - Portfolio Tracker", recipients=[email])
        msg.body = f"Welcome to Portfolio Tracker!\n\nPlease verify your email:\n{verification_link}\n\nThis link expires in 24 hours."
        mail.send(msg)
        return jsonify({'success': True, 'message': 'Verification email sent! Please check your inbox.'}), 200
    except Exception as e:
        logger.exception("Failed to send verification email: %s", e)
        try:
            db_query("DELETE FROM users WHERE email = %s", (email,), commit=True)
        except Exception:
            logger.exception("Failed to rollback user creation for %s", email)
        return jsonify({'success': False, 'error': 'Failed to send verification email'}), 500

@app.route('/verify/<token>')
def verify_email(token):
    try:
        row = db_query("SELECT id, email, meta FROM users WHERE meta->>'verification_token' = %s LIMIT 1", (token,), fetchone=True)
        if not row:
            return jsonify({'success': False, 'error': 'Invalid verification link'}), 400
        meta = row.get('meta') or {}
        created_at_str = meta.get('created_at')
        if created_at_str:
            created_at = datetime.fromisoformat(created_at_str)
            if (datetime.utcnow() - created_at).days > 1:
                return jsonify({'success': False, 'error': 'Verification link expired'}), 400
        email = row['email']
        db_query("""
            UPDATE users
            SET verified = TRUE,
                meta = (meta - 'verification_token')::jsonb,
                updated_at = NOW()
            WHERE email = %s
        """, (email,), commit=True)
        return jsonify({'success': True, 'message': 'Email verified successfully!'}), 200
    except Exception as e:
        logger.exception("verify_email error: %s", e)
        return jsonify({'success': False, 'error': 'Invalid verification link'}), 400

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

# ---------- Utility: get_user_id for requests ----------
def get_request_user_id():
    auth_header = request.headers.get('Authorization') or ''
    if auth_header.startswith('Bearer '):
        token = auth_header.split(' ', 1)[1].strip()
        uid = verify_jwt(token)
        if uid:
            return uid
    try:
        if current_user and current_user.is_authenticated:
            return current_user.id
    except Exception:
        pass
    return None

# ---------- Transactions helpers (DB-backed) ----------
def fetch_transactions_for_user(user_id):
    rows = db_query(
        "SELECT type, stock, quantity, price, to_char(date,'YYYY-MM-DD') AS date, notes FROM transactions WHERE user_id = %s ORDER BY date ASC, created_at ASC;",
        (user_id,), fetchall=True
    )
    if not rows:
        return []
    txs = []
    for r in rows:
        txs.append({'type': r['type'], 'stock': r['stock'], 'quantity': int(r['quantity']), 'price': float(r['price']), 'date': r['date'], 'notes': r.get('notes') or ''})
    return txs

# ---------- Portfolio / Transactions endpoints (DB-backed) ----------
@app.route('/api/transactions', methods=['GET', 'POST', 'OPTIONS'])
@token_required
def transactions_api(user_id):
    if request.method == 'OPTIONS':
        response = make_response()
        origin = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = "GET, POST, OPTIONS"
        response.headers['Access-Control-Allow-Headers'] = "Content-Type, Authorization"
        response.headers['Access-Control-Allow-Credentials'] = "true"
        return response

    if request.method == 'GET':
        try:
            transactions = fetch_transactions_for_user(user_id)
            enhanced = []
            for tx in transactions:
                stock_info = get_stock_info(tx['stock']) or {}
                enhanced.append({**tx, 'name': stock_info.get('shortName', tx['stock']), 'value': tx['quantity'] * tx['price']})
            realized_gains, initial_investment, remaining_cost_basis, remaining_qty = calculate_realized_and_initial_investment(transactions)
            realized_gains_total = sum(realized_gains.values()) if realized_gains else 0
            portfolio_irr = calculate_portfolio_irr(transactions)
            stock_performance = []
            for stock, gain in (realized_gains or {}).items():
                stock_info = get_stock_info(stock) or {}
                stock_performance.append({
                    'ticker': stock,
                    'name': stock_info.get('shortName', stock),
                    'realizedGain': gain,
                    'irr': (gain / initial_investment.get(stock, 1)) * 100 if initial_investment.get(stock, 0) > 0 else 0
                })
            return jsonify({'success': True, 'transactions': enhanced, 'stockPerformance': stock_performance, 'realizedGainsTotal': realized_gains_total, 'portfolioIRR': portfolio_irr, 'current_user': {'id': str(user_id), 'is_authenticated': True}})
        except Exception as e:
            logger.exception("Error fetching transactions: %s", e)
            return jsonify({'success': False, 'error': 'Failed to load transactions'}), 500

    # POST: perform per-user lock + check + insert in same DB transaction to reduce race conditions
    try:
        data = request.get_json() or request.form
        tx_type = (data.get('type') or '').title()
        stock = (data.get('stock') or '').upper()
        quantity = int(data.get('quantity'))
        price = float(data.get('price'))
        date_str = data.get('date')
        notes = data.get('notes')
        if tx_type not in ('Buy', 'Sell'):
            return jsonify({'success': False, 'error': 'Invalid transaction type'}), 400
        if not stock or quantity <= 0 or price < 0 or not date_str:
            return jsonify({'success': False, 'error': 'Missing or invalid fields'}), 400
        try:
            date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
        except Exception:
            return jsonify({'success': False, 'error': 'Date must be YYYY-MM-DD'}), 400
        if date_obj > datetime.utcnow().date():
            return jsonify({'success': False, 'error': 'Transaction date cannot be in the future'}), 400

        # Use a dedicated connection to lock the user's row, check qty and insert in same transaction
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                # Lock the user row to serialize per-user transaction modifications
                cur.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user_id,))
                # compute current_qty using the locked snapshot
                cur.execute("SELECT COALESCE(SUM(CASE WHEN type='Buy' THEN quantity ELSE -quantity END),0) as qty FROM transactions WHERE user_id = %s AND UPPER(stock) = %s;", (user_id, stock))
                row = cur.fetchone()
                current_qty = int(row[0]) if row and row[0] is not None else 0
                if tx_type == 'Sell' and quantity > current_qty:
                    conn.rollback()
                    release_conn(conn)
                    return jsonify({'success': False, 'error': f"Cannot sell {quantity} shares, only {current_qty} available"}), 400
                cur.execute("INSERT INTO transactions (user_id, type, stock, quantity, price, date, notes, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())", (user_id, tx_type, stock, quantity, price, date_str, notes))
                conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                logger.exception("Rollback failed")
            logger.exception("Transaction insertion failed")
            raise
        finally:
            release_conn(conn)

        transactions = fetch_transactions_for_user(user_id)
        enhanced = []
        for tx in transactions:
            stock_info = get_stock_info(tx['stock']) or {}
            enhanced.append({**tx, 'name': stock_info.get('shortName', tx['stock']), 'value': tx['quantity'] * tx['price']})
        return jsonify({'success': True, 'transactions': enhanced}), 201
    except Exception as e:
        logger.exception("Invalid transaction input: %s", e)
        return jsonify({'success': False, 'error': f"Invalid input: {str(e)}"}), 400

@app.route('/api/portfolio', methods=['GET', 'OPTIONS'])
@token_required
def portfolio_tracker_api(user_id):
    if request.method == 'OPTIONS':
        response = make_response()
        origin = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = "GET, OPTIONS"
        response.headers['Access-Control-Allow-Headers'] = "Content-Type, Authorization"
        response.headers['Access-Control-Allow-Credentials'] = "true"
        return response

    try:
        # fetch user email for compatibility with old payload which used email as id
        user_row = get_user_by_id(user_id)
        user_email = user_row.get('email') if user_row else None

        transactions = fetch_transactions_for_user(user_id)
        holdings = compute_holdings_from_transactions(transactions)

        # If no holdings, return same as old file-based behaviour
        if not holdings:
            return jsonify({'success': False, 'error': 'No holdings found.'}), 200

        portfolio_data = []
        total_value = 0.0
        total_cost = 0.0
        sector_values = defaultdict(float)

        realized_gains, initial_investment, remaining_cost_basis, remaining_qty = calculate_realized_and_initial_investment(transactions)

        for symbol, h in holdings.items():
            stock_info = get_stock_info(symbol) or {}
            qty = h['quantity']
            avg_cost = h.get('avg_cost', 0.0)
            total_cost_stock = h.get('total_cost', 0.0)
            current_price = float(stock_info.get('price', 0.0) or 0.0)
            current_value = current_price * qty
            realized_gain = realized_gains.get(symbol, 0.0)
            unrealized_gain = current_value - remaining_cost_basis.get(symbol, total_cost_stock)
            gain_loss = realized_gain + unrealized_gain
            denom = remaining_cost_basis.get(symbol, total_cost_stock) + realized_gain
            gain_pct = (gain_loss / denom) * 100 if denom > 0 else 0

            # keep the same name-selection as the old code
            name = stock_info.get('shortName') or stock_info.get('longName') or stock_info.get('name') or symbol

            entry = {
                'Ticker': symbol,
                'Name': name,
                'Quantity': qty,
                'Investment Date': h.get('first_buy_date', 'N/A'),
                'Exchange': stock_info.get('exchange', 'N/A'),
                'Currency': stock_info.get('currency', 'N/A'),
                'Total Cost': total_cost_stock,
                'Avg Cost/Share': avg_cost,
                'CMP': current_price,
                # preserve old key names exactly (note: old used fallback alternatives)
                '52w High': stock_info.get('52w_high') or stock_info.get('52WeekHigh') or 0,
                '52w Low': stock_info.get('52w_low') or stock_info.get('52WeekLow') or 0,
                'Current Value': current_value,
                'Gain/Loss': gain_loss,
                'Gain/Loss %': gain_pct,
                'Unrealized Gains': unrealized_gain,
                'Sector': stock_info.get('sector', 'N/A'),
            }

            portfolio_data.append(entry)
            total_value += current_value
            total_cost += total_cost_stock
            sector_values[stock_info.get('sector', 'Other')] += current_value

        # AllocationPercent computed after total_value known (same as old)
        for entry in portfolio_data:
            cv = entry.get('Current Value', 0)
            entry['AllocationPercent'] = (cv / total_value) * 100 if total_value > 0 else 0

        df = pd.DataFrame(portfolio_data)

        return jsonify({
            'success': True,
            'totalValue': total_value,
            'totalCost': total_cost,
            'totalGain': (total_value - total_cost),
            'totalGainPercent': ((total_value - total_cost) / total_cost * 100) if total_cost else 0,
            'portfolioTableData': df.to_dict(orient='records'),
            'marketData': get_market_data(),
            # old did not include DB risk, but we can still include latest if present (safe superset)
            'latestRiskAssessment': (db_query("SELECT profile_json FROM user_risk_profiles WHERE user_id = %s ORDER BY created_at DESC LIMIT 1;", (user_id,), fetchone=True) or {}).get('profile_json'),
            'current_user': {
                'id': str(user_id),
                'email': user_email,   # compatibility: old used email as id; frontend can keep using email if desired
                'is_authenticated': True
            }
        })
    except Exception as e:
        logger.exception("portfolio_tracker_api error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to load portfolio'}), 500


@app.route('/api/valuation', methods=['GET', 'OPTIONS'])
@token_required
def valuation_dashboard_api(user_id):
    if request.method == 'OPTIONS':
        response = make_response()
        origin = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = "GET, OPTIONS"
        response.headers['Access-Control-Allow-Headers'] = "Content-Type, Authorization"
        response.headers['Access-Control-Allow-Credentials'] = "true"
        return response

    try:
        transactions = fetch_transactions_for_user(user_id)
        if not transactions:
            return jsonify({'success': False, 'error': "No transactions found"}), 404

        holdings = compute_holdings_from_transactions(transactions)
        if not holdings:
            return jsonify({'success': False, 'error': "No current holdings to value"}), 404

        total_value = 0.0
        valuation_data = {}

        for symbol, h in holdings.items():
            try:
                stock_info = get_stock_info(symbol) or {}
                # prefer cached price from get_stock_info when possible
                current_price = float(stock_info.get('price', 0.0) or 0.0)
                if not current_price:
                    hist = yf.Ticker(symbol).history(period='1d')
                    current_price = float(hist['Close'].iloc[-1]) if not hist.empty else h.get('avg_cost', 0.0)

                qty = h['quantity']
                current_value = current_price * qty
                total_value += current_value

                # include the full set of valuation keys the old version returned
                valuation_data[symbol] = {
                    'Name': stock_info.get('shortName', symbol),
                    'Currency': stock_info.get('currency', 'USD'),
                    'CurrentPrice': current_price,
                    'Quantity': qty,
                    'CurrentValue': current_value,
                    'AvgCost': h.get('avg_cost', 0.0),
                    'UnrealizedGain': current_value - (h.get('avg_cost', 0.0) * qty)
                }
            except Exception as e:
                logger.exception("Error processing %s: %s", symbol, e)
                continue

        # augment with the same financial ratios and keys the old version exposed
        for symbol, data in valuation_data.items():
            try:
                stock_info = get_stock_info(symbol) or {}
                allocation_pct = (data['CurrentValue'] / total_value * 100) if total_value > 0 else 0
                data.update({
                    'AllocationPercent': allocation_pct,
                    '52wHigh': stock_info.get('52w_high', data['CurrentPrice']),
                    '52wLow': stock_info.get('52w_low', data['CurrentPrice']),
                    'MarketCap': stock_info.get('marketCap', 'N/A'),
                    'TrailingPE': stock_info.get('trailingPE', 'N/A'),
                    'ForwardPE': stock_info.get('forwardPE', 'N/A'),
                    'PEGRatio': stock_info.get('pegRatio', 'N/A'),
                    'PriceToSales': stock_info.get('priceToSalesTrailing12Months', 'N/A'),
                    'PriceToBook': stock_info.get('priceToBook', 'N/A'),
                    'EV/Revenue': stock_info.get('enterpriseToRevenue', 'N/A'),
                    'EV/EBITDA': stock_info.get('enterpriseToEbitda', 'N/A'),
                    'ProfitMargin': stock_info.get('profitMargins', 'N/A'),
                    'ROA': stock_info.get('returnOnAssets', 'N/A'),
                    'ROE': stock_info.get('returnOnEquity', 'N/A'),
                    'Revenue': stock_info.get('totalRevenue', 'N/A'),
                    'NetIncome': stock_info.get('netIncomeToCommon', 'N/A'),
                    'EPS': stock_info.get('trailingEps', 'N/A'),
                    'TotalCash': stock_info.get('totalCash', 'N/A'),
                    'DebtEquity': stock_info.get('debtToEquity', 'N/A'),
                    'FreeCashFlow': stock_info.get('freeCashflow', 'N/A'),
                })
            except Exception:
                continue

        return jsonify({
            'success': True,
            'valuationData': valuation_data,
            'tickers': list(valuation_data.keys()),
            'totalValue': total_value,
            'current_user': {'id': str(user_id), 'is_authenticated': True}
        })
    except Exception as e:
        logger.exception("valuation_dashboard_api error: %s", e)
        return jsonify({'success': False, 'error': f"Error loading valuation data: {str(e)}"}), 500


@app.route('/api/clear_transactions', methods=['POST', 'OPTIONS'])
@token_required
def clear_transactions_api(user_id):
    if request.method == 'OPTIONS':
        response = make_response()
        origin = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = "POST, OPTIONS"
        response.headers['Access-Control-Allow-Headers'] = "Content-Type, Authorization"
        response.headers['Access-Control-Allow-Credentials'] = "true"
        return response
    try:
        # delete all transactions for user (DB-backed equivalent of removing the file)
        db_query("DELETE FROM transactions WHERE user_id = %s", (user_id,), commit=True)
        return jsonify({'success': True, 'message': "All transactions cleared successfully."}), 200
    except Exception as e:
        logger.exception("clear_transactions_api error: %s", e)
        return jsonify({'success': False, 'error': f"Error clearing transactions: {str(e)}"}), 500

@app.route('/api/ping', methods=['GET'])
def ping():
    return jsonify({'ping': 'pong'})

# ---------- End of file ----------
