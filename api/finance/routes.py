# api/finance/routes.py
import json
import logging
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, make_response
from collections import defaultdict
import pandas as pd
import yfinance as yf
from decimal import Decimal

from api.auth.auth import google_jwt_required
from api.database.db import db_query, safe_str
from api.finance.transactions.csv_upload import validate_and_normalize_transaction, parse_csv_string
from api.finance.models import fetch_transactions_for_user, insert_transaction_locked
from api.finance.utils import (
    get_stock_info,
    compute_holdings_from_transactions,
    calculate_portfolio_xirr,
    capital_gains_breakdown,
    _sanitize_obj,
)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

finance_bp = Blueprint('finance_bp', __name__)


# ---------------------- Helper: handle OPTIONS ----------------------
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


# ---------------------- Helper: enhance transactions list ----------------------
def _enhance_transactions(transactions):
    """Attach market name and value to transactions"""
    enhanced = []
    for tx in transactions:
        try:
            stock_info = get_stock_info(tx['stock']) or {}
            enhanced.append({
                **tx,
                'name': stock_info.get('shortName', tx['stock']),
                'value': tx['quantity'] * tx['price'],
                'currency': stock_info.get('currency', 'N/A'),
                'exchange': stock_info.get('exchange', 'N/A'),
            })
        except Exception:
            enhanced.append(tx)
    return enhanced


# ---------------------- Bulk upload ----------------------
@finance_bp.route('/api/transactions/bulk', methods=['POST', 'OPTIONS'])
@google_jwt_required
def transactions_bulk_api():
    if request.method == 'OPTIONS':
        return _cors_options()

    user = request.user
    user_id = user.get("id")
    user_email = user.get("email")
    if not user_id:
        return jsonify({'success': False, 'error': "user_id missing"}), 400

    try:
        payload = None
        if request.is_json:
            payload = request.get_json()
        else:
            payload = request.form.to_dict() or {}
            if 'csv' in payload and payload['csv'].strip():
                csv_rows = parse_csv_string(payload['csv'])
                payload = {'transactions': csv_rows}

        transactions = payload.get('transactions') if isinstance(payload, dict) else None
        if transactions is None:
            return jsonify({'success': False, 'error': "No transactions provided"}), 400
        if not isinstance(transactions, list):
            return jsonify({'success': False, 'error': "transactions must be an array"}), 400

        valid_rows = []
        errors = []

        # Validate all rows first
        for idx, raw in enumerate(transactions):
            normalized, row_errors = validate_and_normalize_transaction(raw)
            if row_errors:
                errors.append({'index': idx, 'errors': row_errors})
            else:
                valid_rows.append((idx, normalized))

        insert_errors = []

        # Insert each valid row
        for idx, row in valid_rows:
            try:
                price_val = row['price']
                if isinstance(price_val, Decimal):
                    price_val = float(price_val)

                insert_transaction_locked(
                    user_id,
                    row['type'],
                    row['stock'],
                    int(row['quantity']),
                    price_val,
                    row['date'],
                    row.get('notes') or None
                )
            except Exception as e:
                logger.exception("Error inserting bulk row for user %s: %s", user_email, e)
                insert_errors.append({'index': idx, 'errors': [str(e)]})

        errors.extend(insert_errors)

        transactions_db = fetch_transactions_for_user(user_id)
        enhanced = _enhance_transactions(transactions_db)

        return jsonify(_sanitize_obj({
            'success': True,
            'insertedCount': len(valid_rows) - len(insert_errors),
            'errors': errors,
            'transactions': enhanced
        })), 200

    except Exception as e:
        logger.exception("Bulk upload error for user %s: %s", user_email, e)
        return jsonify({'success': False, 'error': 'Failed processing bulk upload'}), 500


# ---------------------- Transactions (GET/POST) ----------------------
@finance_bp.route('/api/transactions', methods=['GET', 'POST', 'OPTIONS'])
@google_jwt_required
def transactions_api():
    if request.method == 'OPTIONS':
        return _cors_options()

    user = request.user
    user_id = user.get("id")
    user_email = user.get("email")
    if not user_id:
        return jsonify({'success': False, 'error': "user_id missing"}), 400

    if request.method == 'GET':
        try:
            transactions = fetch_transactions_for_user(user_id)
            enhanced = _enhance_transactions(transactions)
            return jsonify(_sanitize_obj({
                'success': True,
                'transactions': enhanced,
                'current_user': {'email': user_email, 'is_authenticated': True}
            }))
        except Exception as e:
            logger.exception("Error fetching transactions for user %s: %s", user_email, e)
            return jsonify({'success': False, 'error': 'Failed to load transactions'}), 500

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

        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
        if date_obj > datetime.utcnow().date():
            return jsonify({'success': False, 'error': 'Transaction date cannot be in the future'}), 400

        insert_transaction_locked(user_id, tx_type, stock, quantity, price, date_str, notes)

        transactions = fetch_transactions_for_user(user_id)
        enhanced = _enhance_transactions(transactions)
        return jsonify(_sanitize_obj({'success': True, 'transactions': enhanced})), 201
    except Exception as e:
        logger.exception("Invalid transaction input for user %s: %s", user_email, e)
        return jsonify({'success': False, 'error': "Invalid input"}), 400


# ---------------------- Portfolio ----------------------
@finance_bp.route('/api/portfolio', methods=['GET', 'OPTIONS'])
@google_jwt_required
def portfolio_tracker_api():
    if request.method == 'OPTIONS':
        return _cors_options()

    user = request.user
    user_id = user.get("id")
    user_email = user.get("email")
    if not user_id:
        return jsonify({'success': False, 'error': "user_id missing"}), 400

    try:
        transactions = fetch_transactions_for_user(user_id)
        holdings = compute_holdings_from_transactions(transactions)
        if not holdings:
            return jsonify({'success': False, 'error': 'No holdings found.'}), 200

        portfolio_xirr = calculate_portfolio_xirr(transactions)

        overview_data = []
        total_value = 0.0
        total_cost = 0.0
        sector_values = defaultdict(float)

        for symbol, h in holdings.items():
            stock_info = get_stock_info(symbol) or {}
            qty = h.get('quantity', 0)
            avg_cost = h.get('avg_cost', 0.0)
            total_cost_stock = h.get('total_cost', 0.0)
            current_price = float(stock_info.get('price', 0.0) or 0.0)
            current_value = current_price * qty
            realized_gain = h.get("realized_gain", 0.0)
            unrealized_gain = h.get("unrealized_gain", 0.0)
            gain_loss = realized_gain + unrealized_gain
            denom = total_cost_stock + realized_gain
            gain_pct = (gain_loss / denom) * 100 if denom else 0

            entry = {
                'Ticker': symbol,
                'Name': stock_info.get('shortName') or symbol,
                'Quantity': qty,
                'Investment Date': h.get('first_buy_date', 'N/A'),
                'Exchange': stock_info.get('exchange', 'N/A'),
                'Currency': stock_info.get('currency', 'N/A'),
                'Total Cost': total_cost_stock,
                'Avg Cost/Share': avg_cost,
                'CMP': current_price,
                'Current Value': current_value,
                'Gain/Loss': gain_loss,
                'Gain/Loss %': gain_pct,
                'Unrealized Gains': unrealized_gain,
                'Sector': stock_info.get('sector', 'N/A'),
            }
            overview_data.append(entry)
            total_value += current_value
            total_cost += total_cost_stock
            sector_values[stock_info.get('sector', 'Other')] += current_value

        for entry in overview_data:
            cv = entry.get('Current Value', 0)
            entry['AllocationPercent'] = (cv / total_value) * 100 if total_value > 0 else 0

        latest_risk = (db_query(
            "SELECT profile_json FROM user_risk_profiles WHERE user_id = %s ORDER BY created_at DESC LIMIT 1;",
            (user_id,), fetchone=True
        ) or {}).get('profile_json')

        return jsonify(_sanitize_obj({
            'success': True,
            'totalValue': total_value,
            'totalCost': total_cost,
            'totalGain': total_value - total_cost,
            'totalGainPercent': ((total_value - total_cost) / total_cost * 100) if total_cost else 0,
            'overviewTabData': overview_data,
            'portfolioXIRR': portfolio_xirr,
            'latestRiskAssessment': latest_risk,
            'current_user': {'email': user_email, 'is_authenticated': True}
        }))

    except Exception as e:
        logger.exception("Portfolio tracker error for user %s: %s", user_email, e)
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------- Valuation ----------------------
@finance_bp.route('/api/valuation', methods=['GET', 'OPTIONS'])
@google_jwt_required
def valuation_dashboard_api():
    if request.method == 'OPTIONS':
        return _cors_options()

    user = request.user
    user_id = user.get("id")
    user_email = user.get("email")
    if not user_id:
        return jsonify({'success': False, 'error': "user_id missing"}), 400

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
            stock_info = get_stock_info(symbol) or {}
            current_price = float(stock_info.get('price', 0.0) or 0.0)
            qty = h.get('quantity', 0)
            current_value = current_price * qty
            total_value += current_value

            valuation_data[symbol] = {
                'Name': stock_info.get('shortName', symbol),
                'Currency': stock_info.get('currency', 'USD'),
                'CurrentPrice': current_price,
                'Quantity': qty,
                'CurrentValue': current_value,
                'AvgCost': h.get('avg_cost', 0.0),
                'UnrealizedGain': h.get('unrealized_gain', 0.0),
                'AllocationPercent': (current_value / total_value * 100) if total_value > 0 else 0,
                **{k: stock_info.get(k) for k in [
                    '52w_high', '52w_low', 'marketCap', 'trailingPE', 'forwardPE', 'pegRatio',
                    'priceToSalesTrailing12Months', 'priceToBook', 'enterpriseToRevenue',
                    'enterpriseToEbitda', 'profitMargins', 'returnOnAssets', 'returnOnEquity',
                    'totalRevenue', 'netIncomeToCommon', 'trailingEps', 'totalCash',
                    'debtToEquity', 'freeCashflow'
                ]}
            }

        return jsonify(_sanitize_obj({
            'success': True,
            'valuationData': valuation_data,
            'tickers': list(valuation_data.keys()),
            'totalValue': total_value,
            'current_user': {'email': user_email, 'is_authenticated': True}
        }))
    except Exception as e:
        logger.exception("Valuation dashboard error for user %s: %s", user_email, e)
        return jsonify({'success': False, 'error': "Error loading valuation data"}), 500


# ---------------------- Capital Gains ----------------------
@finance_bp.route('/api/capital_gains', methods=['GET', 'OPTIONS'])
@google_jwt_required
def capital_gains_api():
    if request.method == 'OPTIONS':
        return _cors_options()

    user = request.user
    user_id = user.get("id")
    user_email = user.get("email")
    if not user_id:
        return jsonify({'success': False, 'error': "user_id missing"}), 400

    try:
        transactions = fetch_transactions_for_user(user_id)
        if not transactions:
            return jsonify({'success': False, 'error': "No transactions found"}), 404

        breakdown = capital_gains_breakdown(transactions)

        # Add IRR per stock
        for stock in breakdown.get('per_stock', {}):
            stock_transactions = [tx for tx in transactions if tx['stock'] == stock]
            if stock_transactions:
                irr_val = calculate_portfolio_xirr(stock_transactions)
                breakdown['per_stock'][stock]['IRR'] = irr_val
            else:
                breakdown['per_stock'][stock]['IRR'] = 0.0

        return jsonify(_sanitize_obj({
            'success': True,
            'capitalGains': breakdown,
            'current_user': {'email': user_email, 'is_authenticated': True}
        }))
    except Exception as e:
        logger.exception("Capital gains error for user %s: %s", user_email, e)
        return jsonify({'success': False, 'error': "Error loading capital gains"}), 500


# ---------------------- Clear Transactions ----------------------
@finance_bp.route('/api/transactions/clear', methods=['POST', 'OPTIONS'])
@google_jwt_required
def clear_transactions_api():
    if request.method == 'OPTIONS':
        return _cors_options()

    user = request.user
    user_id = user.get("id")
    if not user_id:
        return jsonify({'success': False, 'error': "user_id missing"}), 400

    try:
        db_query("DELETE FROM transactions WHERE user_id = %s;", (user_id,), commit=True)
        return jsonify({'success': True, 'message': 'Transactions cleared.'})
    except Exception as e:
        logger.exception("Error clearing transactions for user %s: %s", user.get("email"), e)
        return jsonify({'success': False, 'error': 'Error clearing transactions'}), 500
