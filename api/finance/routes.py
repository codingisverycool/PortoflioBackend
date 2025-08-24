# api/finance/routes.py
import json
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, make_response
from collections import defaultdict
import pandas as pd

from api.auth.auth import google_jwt_required
from api.database.db import db_query, safe_str
from api.finance.models import fetch_transactions_for_user, insert_transaction_locked
from api.finance.utils import (
    get_stock_info,
    calculate_realized_and_initial_investment,
    compute_holdings_from_transactions,
    calculate_portfolio_irr
)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

finance_bp = Blueprint('finance_bp', __name__)

# ----------------------
# Helper: handle OPTIONS
# ----------------------
def _cors_options():
    resp = make_response()
    origin = request.headers.get('Origin', '*')
    resp.headers.update({
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': "GET, POST, OPTIONS",
        'Access-Control-Allow-Headers': "Content-Type, Authorization",
        'Access-Control-Allow-Credentials': "true"
    })
    return resp

# ----------------------
# Helper: fetch UUID from email
# ----------------------
def get_user_id_by_email(email: str) -> str | None:
    if not email:
        return None
    row = db_query("SELECT id FROM users WHERE email = %s LIMIT 1", (email,), fetchone=True)
    return row['id'] if row else None

# --- Transactions ---
@finance_bp.route('/api/transactions', methods=['GET', 'POST', 'OPTIONS'])
@google_jwt_required
def transactions_api():
    user_email = request.user_info.get("email")
    if request.method == 'OPTIONS':
        return _cors_options()

    user_id = get_user_id_by_email(user_email)
    if not user_id:
        return jsonify({'success': False, 'error': "User not found"}), 404

    if request.method == 'GET':
        try:
            transactions = fetch_transactions_for_user(user_id)
            enhanced = []
            for tx in transactions:
                stock_info = get_stock_info(tx['stock']) or {}
                enhanced.append({
                    **tx,
                    'name': stock_info.get('shortName', tx['stock']),
                    'value': tx['quantity'] * tx['price']
                })
            realized_gains, initial_investment, remaining_cost_basis, remaining_qty = calculate_realized_and_initial_investment(transactions)
            realized_gains_total = sum(realized_gains.values()) if realized_gains else 0
            portfolio_irr = calculate_portfolio_irr(transactions)
            stock_performance = []
            for stock, gain in (realized_gains or {}).items():
                stock_info = get_stock_info(stock) or {}
                denom = initial_investment.get(stock, 1)
                stock_performance.append({
                    'ticker': stock,
                    'name': stock_info.get('shortName', stock),
                    'realizedGain': gain,
                    'irr': (gain / denom) * 100 if denom else 0
                })
            return jsonify({
                'success': True,
                'transactions': enhanced,
                'stockPerformance': stock_performance,
                'realizedGainsTotal': realized_gains_total,
                'portfolioIRR': portfolio_irr,
                'current_user': {'email': user_email, 'is_authenticated': True}
            })
        except Exception as e:
            logger.exception("Error fetching transactions for user %s: %s", user_email, e)
            return jsonify({'success': False, 'error': 'Failed to load transactions'}), 500

    # POST
    try:
        data = request.get_json() or request.form
        tx_type = safe_str(data.get('type')).title()
        stock = safe_str(data.get('stock')).upper()
        quantity = int(data.get('quantity'))
        price = float(data.get('price'))
        date_str = safe_str(data.get('date'))
        notes = safe_str(data.get('notes'))

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

        # Insert transaction safely with per-user lock
        try:
            insert_transaction_locked(user_id, tx_type, stock, quantity, price, date_str, notes)
        except ValueError as ve:
            return jsonify({'success': False, 'error': str(ve)}), 400

        # Return updated transactions
        transactions = fetch_transactions_for_user(user_id)
        enhanced = []
        for tx in transactions:
            stock_info = get_stock_info(tx['stock']) or {}
            enhanced.append({**tx, 'name': stock_info.get('shortName', tx['stock']), 'value': tx['quantity'] * tx['price']})
        return jsonify({'success': True, 'transactions': enhanced}), 201
    except Exception as e:
        logger.exception("Invalid transaction input for user %s: %s", user_email, e)
        return jsonify({'success': False, 'error': "Invalid input"}), 400

# --- Portfolio ---
@finance_bp.route('/api/portfolio', methods=['GET', 'OPTIONS'])
@google_jwt_required
def portfolio_tracker_api():
    user_email = request.user_info.get("email")
    if request.method == 'OPTIONS':
        return _cors_options()

    user_id = get_user_id_by_email(user_email)
    if not user_id:
        return jsonify({'success': False, 'error': "User not found"}), 404

    try:
        transactions = fetch_transactions_for_user(user_id)
        holdings = compute_holdings_from_transactions(transactions)
        if not holdings:
            return jsonify({'success': False, 'error': 'No holdings found.'}), 200

        portfolio_data = []
        total_value = total_cost = 0.0
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
            gain_pct = (gain_loss / denom) * 100 if denom else 0
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
                '52w High': stock_info.get('52w_high', 0),
                '52w Low': stock_info.get('52w_low', 0),
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

        for entry in portfolio_data:
            cv = entry.get('Current Value', 0)
            entry['AllocationPercent'] = (cv / total_value) * 100 if total_value > 0 else 0

        df = pd.DataFrame(portfolio_data)
        latest_risk = (db_query(
            "SELECT profile_json FROM user_risk_profiles WHERE user_id = %s ORDER BY created_at DESC LIMIT 1;",
            (user_id,), fetchone=True
        ) or {}).get('profile_json')

        return jsonify({
            'success': True,
            'totalValue': total_value,
            'totalCost': total_cost,
            'totalGain': total_value - total_cost,
            'totalGainPercent': ((total_value - total_cost) / total_cost * 100) if total_cost else 0,
            'portfolioTableData': df.to_dict(orient='records'),
            'marketData': {
                'nasdaq': {'price': 0, 'change': 0, 'change_pct': 0},
                'sp500': {'price': 0, 'change': 0, 'change_pct': 0},
                'dow': {'price': 0, 'change': 0, 'change_pct': 0}
            },
            'latestRiskAssessment': latest_risk,
            'current_user': {'email': user_email, 'is_authenticated': True}
        })
    except Exception as e:
        logger.exception("Portfolio tracker error for user %s: %s", user_email, e)
        return jsonify({'success': False, 'error': 'Failed to load portfolio'}), 500

# --- Valuation ---
@finance_bp.route('/api/valuation', methods=['GET', 'OPTIONS'])
@google_jwt_required
def valuation_dashboard_api():
    user_email = request.user_info.get("email")
    if request.method == 'OPTIONS':
        return _cors_options()

    user_id = get_user_id_by_email(user_email)
    if not user_id:
        return jsonify({'success': False, 'error': "User not found"}), 404

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
                current_price = float(stock_info.get('price', 0.0) or 0.0)
                qty = h['quantity']
                current_value = current_price * qty
                total_value += current_value

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
                logger.exception("Valuation error for %s: %s", symbol, e)
                continue

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
            'current_user': {'email': user_email, 'is_authenticated': True}
        })
    except Exception as e:
        logger.exception("Valuation dashboard error for user %s: %s", user_email, e)
        return jsonify({'success': False, 'error': "Error loading valuation data"}), 500

# --- Clear transactions ---
@finance_bp.route('/api/clear_transactions', methods=['POST', 'OPTIONS'])
@google_jwt_required
def clear_transactions_api():
    user_email = request.user_info.get("email")
    if request.method == 'OPTIONS':
        return _cors_options()

    user_id = get_user_id_by_email(user_email)
    if not user_id:
        return jsonify({'success': False, 'error': "User not found"}), 404

    try:
        db_query("DELETE FROM transactions WHERE user_id = %s", (user_id,), commit=True)
        return jsonify({'success': True, 'message': "All transactions cleared successfully."}), 200
    except Exception as e:
        logger.exception("Clear transactions error for user %s: %s", user_email, e)
        return jsonify({'success': False, 'error': "Error clearing transactions"}), 500
