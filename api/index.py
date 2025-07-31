from flask import Flask, request, url_for, jsonify, make_response, session
from flask_cors import CORS 
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import yfinance as yf
import plotly.graph_objs as go
import plotly.express as px
import plotly.io as pio
import base64
import json
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import secrets
from collections import defaultdict
import pandas as pd
import logging
from functools import wraps

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["https://turiyaportfolioplatform-9v5cm5rvi-aaryans-projects-56d3a379.vercel.app"])
app.secret_key = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCe1IMBxPm037d\nT43H/Kti/S0ZPvf0o6W7kEwk3Ma/9NpK86HHZ8QFVvzyUtvBqWgV3SyKyAzoYfou\nyIb7UIX2XB0Yl86NsiV15lPSKgWRCA8Ejh29M7dz8Yxha9qFAfwgEtCpPvyCkBSn\nd2CuEB/Hk7MFjMJkYblSNY9j87dYoWlkJv6Y3k29eyFP4eI/Ivzj0sX8A3fpn4P5\nLltlRrzG6yvaY+m/Rd9G9p9+dumVwwgvZm/CVIN3ZU1zQV168Wv4jyzT87grsuOU\nfox5RDM63HBs06EaKq1fZh3wBLruoCOYe4xUMIXY63OkujTaJQRzSZ1cOSo5iUZ1\neaIyOeQjAgMBAAECggEABLO3lZvcMtH9OLuSKXol6KRHYVtg4lTMjn7cIG4IDh8M\n4hAG4svS9PAX+IHhV0rRvemViJtymHG5+0SU4uGdA4pRl8Uf1NQwTKvvbd7fOJTx\nzAHlnSvxbQezha12YI3eOyZJTjY8I6n5Hd1ohHzWT9x10RYIoyWrtd2epGOBlM5z\ncQlARXnk3iz/0n/GqMzNJ8mn7R1S1l1t35y9jTmthiq2FzYa+anFU29bnRuE8FD3\nagFf1y0fX9QGAhbbNPeXh8bn/8qfwxB7wfWpB7NlfLZ3gLTZIV7BRXe3jJztpj15\n6iWPp6fZfDKTYeIbEK+8k/GcDluOod9Mj9WUxfKUpQKBgQDqJ7WQT/lH0eL6vioB\nNQfh25KWyvCH/NU/T9LhZdJkiNweqQ9nbc9kqRNitT3JV6tSlmc2nBESQnxErtq1\nFc4R1b9ryKMDq4iowtC/5WxvQUpYddaBZ7i5pivd2eYuVuF5aFNZHguIRpQ97v0b\n35w2Mr5XnLhoc5E2lKIQgXnS3QKBgQDUoBkBRbemBSShw02LJ8Jp3JPr2ylnDH6e\nABlzYRVihuL7wZN9RCy56sNSCZXbXJAedT6U6QlFRNdJ3BeaxXajq1gmt690VC35\neaOfR+tI2DcEToAZR6tI6ced+7UBNzB2YvkixxFWbMRVi33FubKwagk2Z5fcxB9A\nkZI9gqWi/wKBgQDOPYOSRJ6QP7HooK5mucrjiH6pCr6pSGybgzd/CCw0GMeoyej\nlfjh9Hn6qyBswydHauomE3iF2MGTzV8duML0uowL54CNrvyDiHRNUUodBCjzmXcC\nK9Vsz4w7r70qe6PFR7qB+BC4S1Iu6t1NO7tfkXpNuOBEP+ZbaLcGSsR+kQKBgCn6\njdVFeXOqskfJsmaV6/lQllfLhkoVGm6BYIT6FunD7c58smzZ5+aw5e0tfUu4469P\nwJJPzAfEBqlLbdGdyMWZj6bdPyO9dvI5RMeuwFI6depAwWO8VaHongOf7WWXCtdk\nxQFLwi2I/d5R0vwVpKTV2onGPCJXCkCKPRAt2hvrAoGBAJ8Rdy6+UUXd7YxJn8/I\nYOG47DL0mk/el0zq60JSFCXjgMrcvHdRpb8ExE+BH9EdgtDljMPQQNfIKKRpKECu\nN5XJk4iDxI+AAVGYj4Q7PgDoQhsBQ3ztYcOXxD07gOHijmqPM4i82bWzNIRNoDxK\njA8UwfdSVK+fLFZ8FHNr/ub0"

logging.basicConfig(level=logging.DEBUG)  # You can use INFO or DEBUG
logger = logging.getLogger(__name__)

# Email configuration
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,  # Only if deployed over HTTPS (e.g., Vercel)
    MAIL_SERVER='smtp.sendgrid.net',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME='apikey',
    MAIL_PASSWORD='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',
    MAIL_DEFAULT_SENDER='aaryanjthaker@gmail.com'
)

mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

USERS_FILE = 'users.json'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, email):
        users = load_users()
        user_data = users.get(email, {})
        self.id = email
        self.email = email
        self.verified = user_data.get('verified', False)

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

# Fetch stock info via yfinance
def get_stock_info(ticker):
    try:
        stock = yf.Ticker(ticker)
        info = stock.info
        price = stock.history(period="1d")['Close'].iloc[-1]
        return {
            'price': price,
            'currency': info.get('currency', 'N/A'),
            'exchange': info.get('exchange', 'N/A'),
            'industry': info.get('industry', 'N/A'),
            'sector': info.get('sector', 'N/A'),
            '52w_high': info.get('fiftyTwoWeekHigh', 'N/A'),
            '52w_low': info.get('fiftyTwoWeekLow', 'N/A')
        }
    except Exception as e:
        print(f"Error fetching data for {ticker}: {e}")
        return None

# Fetch current market index data
def get_market_data():
    symbols = {
        'nasdaq': '^IXIC',
        'sp500': '^GSPC',
        'dow': '^DJI'
    }
    market_data = {}
    for name, symbol in symbols.items():
        try:
            stock = yf.Ticker(symbol)
            hist = stock.history(period='5d')  # increased to 5 days for more reliable data

            if len(hist) < 2:
                print(f"Warning: Not enough historical data for {name} ({symbol})")
                market_data[name] = {'price': 0, 'change': 0, 'change_pct': 0}
                continue

            current = hist['Close'].iloc[-1]
            prev_close = hist['Close'].iloc[-2]
            change = current - prev_close
            change_pct = (change / prev_close) * 100

            market_data[name] = {
                'price': current,
                'change': change,
                'change_pct': change_pct / 100  # decimal format for frontend
            }

        except Exception as e:
            print(f"Error fetching {name} data ({symbol}): {e}")
            market_data[name] = {'price': 0, 'change': 0, 'change_pct': 0}

    # Make sure all keys exist so frontend won't fail
    for key in ['nasdaq', 'sp500', 'dow']:
        if key not in market_data:
            market_data[key] = {'price': 0, 'change': 0, 'change_pct': 0}

    return market_data

# Calculate annualized IRR from transaction list
def calculate_portfolio_irr(transactions):
    cash_flows = []
    dates = []
    for tx in transactions:
        amount = tx['quantity'] * tx['price']
        if tx['type'] == 'Buy':
            amount = -amount  # investment outflow
        cash_flows.append(amount)
        dates.append(datetime.strptime(tx['date'], '%Y-%m-%d'))
    if not cash_flows:
        return 0
    try:
        total_investment = sum(cf for cf in cash_flows if cf < 0)
        total_return = sum(cf for cf in cash_flows if cf > 0)
        days_held = (max(dates) - min(dates)).days if len(dates) > 1 else 1
        annualized_return = ((total_return / abs(total_investment)) ** (365/days_held) - 1) * 100
        return annualized_return
    except Exception:
        return 0

# Generate pie chart and return base64 encoded PNG
def fig_to_base64_img(fig):
    img_bytes = fig.to_image(format="png")
    return base64.b64encode(img_bytes).decode('utf8')


def generate_pie_chart(values, labels, title):
    fig = px.pie(
        names=labels,
        values=values,
        title=title
    )
    return fig_to_base64_img(fig)


def generate_bar_chart(df, value_col, label_col, title):
    df_sorted = df.sort_values(value_col)
    colors = ['green' if x >= 0 else 'red' for x in df_sorted[value_col]]
    fig = px.bar(
        df_sorted,
        x=value_col,
        y=label_col,
        orientation='h',
        title=title,
        color=df_sorted[value_col].apply(lambda x: 'Positive' if x >= 0 else 'Negative'),
        color_discrete_map={'Positive': 'green', 'Negative': 'red'}
    )
    return fig_to_base64_img(fig)


def generate_treemap(df, size_col, label_col, color_col, title):
    fig = px.treemap(
        df,
        path=[label_col],
        values=size_col,
        color=color_col,
        color_continuous_scale='RdYlGn',
        title=title
    )
    return fig_to_base64_img(fig)

def calculate_realized_and_initial_investment(transactions): 
    lots = {}  # FIFO lots per stock
    realized_gains = {}
    initial_investment = {}

    for tx in sorted(transactions, key=lambda x: x['date']):
        stock = tx['stock'].upper()
        qty = int(tx['quantity'])
        price = float(tx['price'])
        type_ = tx['type']

        if stock not in lots:
            lots[stock] = []
            realized_gains[stock] = 0.0
            initial_investment[stock] = 0.0

        if type_ == 'Buy':
            lots[stock].append({'quantity': qty, 'price': price})
            initial_investment[stock] += qty * price

        elif type_ == 'Sell':
            sell_qty = qty
            sell_proceeds = sell_qty * price
            cost_removed = 0.0

            if stock not in lots or not lots[stock]:
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
        qty = sum(lot['quantity'] for lot in stock_lots)
        cost = sum(lot['quantity'] * lot['price'] for lot in stock_lots)
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
            holdings[stock] = {
                'stock': stock,
                'quantity': 0,
                'total_cost': 0.0,
                'first_buy_date': date
            }
            lots[stock] = []
            realized_gains[stock] = 0.0

        if type_ == 'Buy':
            lots[stock].append({'quantity': quantity, 'price': price})
            holdings[stock]['quantity'] += quantity
            holdings[stock]['total_cost'] += quantity * price
            holdings[stock]['first_buy_date'] = min(holdings[stock]['first_buy_date'], date)

        elif type_ == 'Sell':
            if holdings[stock]['quantity'] < quantity:
                continue  # Skip invalid sells

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

    for stock in holdings:
        remaining_cost = holdings[stock]['total_cost']
        qty = holdings[stock]['quantity']
        avg_cost = remaining_cost / qty if qty > 0 else 0.0
        holdings[stock]['avg_cost'] = avg_cost
        holdings[stock]['realized_gain'] = realized_gains[stock]

    return holdings

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or request.form
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    logger.debug(f"Login attempt: email={email}, password_length={len(password)}")

    users = load_users()
    user = users.get(email)

    if not user:
        logger.warning(f"Login failed: user '{email}' not found")
        return jsonify({'success': False, 'error': 'User not found'}), 404

    if not user.get('verified'):
        logger.warning(f"Login failed: user '{email}' not verified")
        return jsonify({'success': False, 'error': 'Email not verified'}), 403

    if not check_password_hash(user['password'], password):
        logger.warning(f"Login failed: wrong password for user '{email}'")
        return jsonify({'success': False, 'error': 'Incorrect password'}), 401

    logger.info(f"Login successful for user '{email}'")
    login_user(User(email))
    return jsonify({'success': True, 'message': 'Login successful'})

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({'success': False, 'error': 'Unauthorized'}), 401


@app.route('/api/register', methods=['POST'])
def register():
    users = load_users()
    data = request.json
    email = data.get('email', '').strip().lower()
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if email in users:
        return jsonify({'success': False, 'error': 'Email already registered'}), 400
    if password != confirm_password:
        return jsonify({'success': False, 'error': 'Passwords do not match'}), 400
    if len(password) < 8:
        return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400

    verification_token = secrets.token_urlsafe(32)

    users[email] = {
        'password': generate_password_hash(password, method='pbkdf2:sha256'),
        'email': email,
        'verified': False,
        'verification_token': verification_token,
        'created_at': datetime.now().isoformat()
    }
    save_users(users)

    try:
        verification_link = url_for('verify_email', token=verification_token, _external=True)
        msg = Message("Verify Your Email - Portfolio Tracker", recipients=[email])
        msg.body = f"""Welcome to Portfolio Tracker!\n\nPlease verify your email:\n{verification_link}\n\nThis link expires in 24 hours."""
        mail.send(msg)
        return jsonify({'success': True, 'message': 'Verification email sent! Please check your inbox.'}), 200

    except Exception as e:
        users.pop(email, None)
        save_users(users)
        return jsonify({'success': False, 'error': 'Failed to send verification email'}), 500


@app.route('/verify/<token>')
def verify_email(token):
    users = load_users()
    for username, user_data in users.items():
        if user_data.get('verification_token') == token:
            created_at = datetime.fromisoformat(user_data.get('created_at', ''))
            if (datetime.now() - created_at).days > 1:
                return jsonify({'success': False, 'error': 'Verification link expired'}), 400

            user_data['verified'] = True
            user_data.pop('verification_token', None)
            save_users(users)
            return jsonify({'success': True, 'message': 'Email verified successfully!'}), 200

    return jsonify({'success': False, 'error': 'Invalid verification link'}), 400

def get_user_data_file():
    return f'user_data/{current_user.id}/portfolio.json'

def load_user_data():
    try:
        with open(get_user_data_file()) as f:
            data = json.load(f)
            return {
                'stock[]': data.get('stock[]', []),
                'quantity[]': data.get('quantity[]', []),
                'investment_date[]': data.get('investment_date[]', []),
                'avg_cost[]': data.get('avg_cost[]', [])
            }
    except:
        return None

def save_user_data(data):
    os.makedirs(os.path.dirname(get_user_data_file()), exist_ok=True)
    with open(get_user_data_file(), 'w') as f:
        json.dump({
            'stock[]': data.getlist('stock[]') if hasattr(data, 'getlist') else data.get('stock[]', []),
            'quantity[]': data.getlist('quantity[]') if hasattr(data, 'getlist') else data.get('quantity[]', []),
            'investment_date[]': data.getlist('investment_date[]') if hasattr(data, 'getlist') else data.get('investment_date[]', []),
            'avg_cost[]': data.getlist('avg_cost[]') if hasattr(data, 'getlist') else data.get('avg_cost[]', [])
        }, f)

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

@app.route('/api/portfolio', methods=['GET'])
@login_required
def portfolio_tracker_api():
    tx_file = os.path.join('user_data', current_user.id, 'transactions.json')
    transactions = []

    if os.path.exists(tx_file):
        with open(tx_file, encoding='utf-8') as f:
            transactions = json.load(f)

    holdings = compute_holdings_from_transactions(transactions)
    if not holdings:
        return jsonify({'success': False, 'error': 'No holdings found.'}), 200

    realized_gains, initial_investment, remaining_cost_basis, remaining_qty = calculate_realized_and_initial_investment(transactions)

    portfolio_data = []
    total_value = 0
    total_cost = 0
    sector_values = defaultdict(float)

    for symbol, h in holdings.items():
        stock_info = get_stock_info(symbol)
        if not stock_info:
            continue

        qty = h['quantity']
        avg_cost = h['avg_cost']
        total_cost_stock = h['total_cost']
        current_price = stock_info['price']
        current_value = current_price * qty
        realized_gain = realized_gains.get(symbol, 0)
        unrealized_gain = current_value - remaining_cost_basis.get(symbol, total_cost_stock)
        gain_loss = realized_gain + unrealized_gain
        denom = remaining_cost_basis.get(symbol, total_cost_stock) + realized_gain
        gain_pct = (gain_loss / denom) * 100 if denom > 0 else 0
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
            '52w High': stock_info.get('52WeekHigh') or stock_info.get('52w_high') or 0,
            '52w Low': stock_info.get('52WeekLow') or stock_info.get('52w_low') or 0,
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

    # Now calculate AllocationPercent after total_value is known
    for entry in portfolio_data:
        cv = entry.get('Current Value')
        entry['AllocationPercent'] = (cv / total_value) * 100 if total_value > 0 else 0

    df = pd.DataFrame(portfolio_data)

    imgData = {}

    try:
        # Stock Allocation Pie Chart
        stock_pie = go.Figure(go.Pie(
            labels=df['Ticker'],
            values=df['AllocationPercent'],
            hole=0,
            textinfo='label+percent',
        ))
        stock_pie.update_layout(title='Stock Allocation')
        imgData['stockPie'] = pio.to_image(stock_pie, format='png', width=600, height=600)
        imgData['stockPie'] = base64.b64encode(imgData['stockPie']).decode('utf-8')

        # Sector Allocation Pie Chart
        sector_labels = list(sector_values.keys())
        sector_vals = list(sector_values.values())
        sector_pie = go.Figure(go.Pie(
            labels=sector_labels,
            values=sector_vals,
            hole=0,
            textinfo='label+percent',
        ))
        sector_pie.update_layout(title='Sector Allocation')
        imgData['sectorPie'] = pio.to_image(sector_pie, format='png', width=600, height=600)
        imgData['sectorPie'] = base64.b64encode(imgData['sectorPie']).decode('utf-8')

        # Gain/Loss Horizontal Bar Chart
        df_sorted = df.sort_values('Gain/Loss')
        colors = ['green' if g >= 0 else 'red' for g in df_sorted['Gain/Loss']]
        gain_bar = go.Figure(go.Bar(
            x=df_sorted['Gain/Loss'],
            y=df_sorted['Ticker'],
            orientation='h',
            marker_color=colors
        ))
        gain_bar.update_layout(title='Gain/Loss', yaxis=dict(autorange="reversed"))
        imgData['gainBar'] = pio.to_image(gain_bar, format='png', width=800, height=400)
        imgData['gainBar'] = base64.b64encode(imgData['gainBar']).decode('utf-8')

        # Treemap Chart
        treemap = go.Figure(go.Treemap(
            labels=[f"{row['Ticker']} (${row['Current Value']/1000:.1f}k)" for _, row in df.iterrows()],
            values=df['Current Value'],
            marker_colors=colors,
            textinfo="label+value"
        ))
        treemap.update_layout(title='Treemap')
        imgData['treemap'] = pio.to_image(treemap, format='png', width=1000, height=600)
        imgData['treemap'] = base64.b64encode(imgData['treemap']).decode('utf-8')

    except Exception as e:
        print(f"Chart Error: {e}")

    return jsonify({
        'success': True,
        'totalValue': total_value,
        'totalCost': total_cost,
        'totalGain': total_value - total_cost,
        'totalGainPercent': (total_value - total_cost) / total_cost * 100 if total_cost else 0,
        'portfolioTableData': df.to_dict(orient='records'),
        'charts': imgData,
        'marketData': get_market_data(),
        'current_user': {
            'id': current_user.id,
            'is_authenticated': True
        }
    })

@app.route('/api/transactions', methods=['GET', 'POST'])
@login_required
def transactions_api():
    user_file = f'user_data/{current_user.id}/transactions.json'
    os.makedirs(os.path.dirname(user_file), exist_ok=True)

    # Load transactions
    if os.path.exists(user_file):
        with open(user_file) as f:
            transactions = json.load(f)
    else:
        transactions = []

    if request.method == 'POST':
        try:
            data = request.json or request.form
            tx_type = data.get('type')
            stock = data.get('stock', '').upper()
            quantity = int(data.get('quantity'))
            price = float(data.get('price'))
            date = data.get('date')

            if tx_type == 'Sell':
                current_qty = sum(tx['quantity'] for tx in transactions if tx['stock'].upper() == stock and tx['type'] == 'Buy') - \
                              sum(tx['quantity'] for tx in transactions if tx['stock'].upper() == stock and tx['type'] == 'Sell')
                if quantity > current_qty:
                    return jsonify({'success': False, 'error': f"Cannot sell {quantity} shares, only {current_qty} available"}), 400

            transactions.append({
                'type': tx_type,
                'stock': stock,
                'quantity': quantity,
                'price': price,
                'date': date
            })

            with open(user_file, 'w') as f:
                json.dump(transactions, f, indent=2)

        except Exception as e:
            return jsonify({'success': False, 'error': f"Invalid input: {str(e)}"}), 400

    # Process performance
    realized_gains, initial_investment, remaining_cost_basis, remaining_qty = \
        calculate_realized_and_initial_investment(transactions)

    realized_gains_total = sum(realized_gains.values())
    portfolio_irr = calculate_portfolio_irr(transactions)

    # Realized gain by stock
    stock_performance = []
    for stock, gain in realized_gains.items():
        stock_info = get_stock_info(stock)
        stock_performance.append({
            'ticker': stock,
            'name': stock_info.get('shortName', stock) if stock_info else stock,
            'realizedGain': gain,
            'irr': (gain / initial_investment.get(stock, 1)) * 100 if initial_investment.get(stock, 0) > 0 else 0
        })

    # Add value & names to transactions
    enhanced_transactions = []
    for tx in transactions:
        stock_info = get_stock_info(tx['stock'])
        enhanced_transactions.append({
            **tx,
            'name': stock_info.get('shortName', tx['stock']) if stock_info else tx['stock'],
            'value': tx['quantity'] * tx['price']
        })

    return jsonify({
    'success': True,
    'transactions': enhanced_transactions,
    'stockPerformance': stock_performance,
    'realizedGainsTotal': realized_gains_total,
    'portfolioIRR': portfolio_irr,
    'current_user': {
        'id': current_user.id,
        'is_authenticated': current_user.is_authenticated,
    }
})


@app.route('/api/valuation', methods=['GET'])
@login_required
def valuation_dashboard_api():
    try:
        tx_file = f'user_data/{current_user.id}/transactions.json'
        if not os.path.exists(tx_file):
            return jsonify({'success': False, 'error': "No transactions found"}), 404

        with open(tx_file) as f:
            transactions = json.load(f)

        holdings = compute_holdings_from_transactions(transactions)
        if not holdings:
            return jsonify({'success': False, 'error': "No current holdings to value"}), 404

        total_value = 0
        valuation_data = {}

        for symbol, h in holdings.items():
            try:
                stock = yf.Ticker(symbol)
                info = stock.info
                hist = stock.history(period='1d')
                current_price = hist['Close'].iloc[-1] if not hist.empty else h['avg_cost']

                qty = h['quantity']
                current_value = current_price * qty
                total_value += current_value

                valuation_data[symbol] = {
                    'Name': info.get('shortName', symbol),
                    'Currency': info.get('currency', 'USD'),
                    'CurrentPrice': current_price,
                    'Quantity': qty,
                    'CurrentValue': current_value,
                    'AvgCost': h['avg_cost'],
                    'UnrealizedGain': current_value - (h['avg_cost'] * qty)
                }

            except Exception as e:
                print(f"Error processing {symbol}: {str(e)}")
                continue

        # Add percentages and valuation ratios
        for symbol, data in valuation_data.items():
            try:
                stock = yf.Ticker(symbol)
                info = stock.info

                allocation_pct = (data['CurrentValue'] / total_value * 100)/100 if total_value > 0 else 0

                data.update({
                    'AllocationPercent': allocation_pct,
                    '52wHigh': info.get('fiftyTwoWeekHigh', data['CurrentPrice']),
                    '52wLow': info.get('fiftyTwoWeekLow', data['CurrentPrice']),
                    'MarketCap': info.get('marketCap', 'N/A'),
                    'TrailingPE': info.get('trailingPE', 'N/A'),
                    'ForwardPE': info.get('forwardPE', 'N/A'),
                    'PEGRatio': info.get('pegRatio', 'N/A'),
                    'PriceToSales': info.get('priceToSalesTrailing12Months', 'N/A'),
                    'PriceToBook': info.get('priceToBook', 'N/A'),
                    'EV/Revenue': info.get('enterpriseToRevenue', 'N/A'),
                    'EV/EBITDA': info.get('enterpriseToEbitda', 'N/A'),
                    'ProfitMargin': info.get('profitMargins', 'N/A'),
                    'ROA': info.get('returnOnAssets', 'N/A'),
                    'ROE': info.get('returnOnEquity', 'N/A'),
                    'Revenue': info.get('totalRevenue', 'N/A'),
                    'NetIncome': info.get('netIncomeToCommon', 'N/A'),
                    'EPS': info.get('trailingEps', 'N/A'),
                    'TotalCash': info.get('totalCash', 'N/A'),
                    'DebtEquity': info.get('debtToEquity', 'N/A'),
                    'FreeCashFlow': info.get('freeCashflow', 'N/A')
                })

            except Exception as e:
                print(f"Error getting valuation data for {symbol}: {str(e)}")
                continue

        return jsonify({
            'success': True,
            'valuationData': valuation_data,
            'tickers': list(valuation_data.keys()),
            'totalValue': total_value,
            'current_user':{
                'id': current_user.id,
                'is_authenticated': current_user.is_authenticated,
            }
        })

    except Exception as e:
        return jsonify({'success': False, 'error': f"Error loading valuation data: {str(e)}"}), 500

@app.route('/api/clear_transactions', methods=['POST'])
@login_required
def clear_transactions_api():
    user_file = f'user_data/{current_user.id}/transactions.json'
    try:
        if os.path.exists(user_file):
            os.remove(user_file)
        return jsonify({
            'success': True,
            'message': "All transactions cleared successfully."
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f"Error clearing transactions: {str(e)}"
        }), 500

@app.route('/api/ping', methods=['GET'])
def ping():
    return jsonify({'ping': 'pong'})