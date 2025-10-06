"""
Updated utils for finance API
- Normalizes yfinance data into predictable keys (price, previousClose, fiftyTwoWeekHigh, fiftyTwoWeekLow, change, change_pct, etc.)
- Adds caching around ticker info to reduce calls
- Implements holdings calculation (FIFO for sells)
- Implements XIRR calculation (Newton method) with terminal value using current market prices
- Implements a simple capital gains breakdown (realized/unrealized, short/long term)
- _sanitize_obj to prepare objects for JSON responses

This file is designed to be robust to missing keys returned by yfinance.
"""

import logging
from datetime import datetime, date
from functools import lru_cache
from typing import List, Dict, Any, Optional, Tuple
import math
from decimal import Decimal

import yfinance as yf

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------- Helpers / Normalization ----------------------

def _to_float_safe(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        if isinstance(v, Decimal):
            return float(v)
        return float(v)
    except Exception:
        try:
            # sometimes strings with commas
            return float(str(v).replace(',', ''))
        except Exception:
            return None


@lru_cache(maxsize=512)
def get_stock_info(ticker: str) -> Dict[str, Any]:
    """Return a normalized stock info dict for the given ticker.

    This version will attempt multiple ticker variants (original, .NS, .BO)
    to improve coverage for Indian tickers. It returns a normalized dict
    including 'symbol' (the resolved symbol) and 'currency'.
    """
    ticker_in = (ticker or '').strip().upper()
    if not ticker_in:
        return {}

    # variants to try in order: exact, <exact>.NS, <exact>.BO
    variants = [ticker_in]
    if "." not in ticker_in:
        variants.extend([f"{ticker_in}.NS", f"{ticker_in}.BO"])

    info_out: Dict[str, Any] = {'symbol': ticker_in}

    last_exception = None
    for symbol_to_try in variants:
        try:
            t = yf.Ticker(symbol_to_try)
            info = {}
            try:
                info = getattr(t, 'info', {}) or {}
            except Exception:
                info = {}

            # if price or meaningful info present, accept this symbol
            price_candidate = None
            try:
                price_candidate = _to_float_safe(
                    info.get('regularMarketPrice') or info.get('currentPrice') or info.get('price') or info.get('lastPrice')
                )
            except Exception:
                price_candidate = None

            # pick helper
            def _pick(*keys, fallback=None):
                for k in keys:
                    if not k:
                        continue
                    v = info.get(k)
                    if v is not None:
                        return v
                return fallback

            # If this variant has any price or shortName, consider it valid
            if price_candidate is None and not _pick('shortName', 'longName', None):
                # not a promising variant — try next
                continue

            # we have a candidate — populate fields and break
            info_out['symbol'] = symbol_to_try
            info_out['shortName'] = _pick('shortName', 'longName', 'name', fallback=symbol_to_try)
            info_out['currency'] = _pick('currency', 'quoteCurrency', fallback='USD')
            info_out['exchange'] = _pick('exchange', 'exchangeName', 'market', fallback=None)
            info_out['sector'] = _pick('sector', fallback=None)
            info_out['marketCap'] = _to_float_safe(_pick('marketCap', 'market_cap'))
            info_out['trailingPE'] = _to_float_safe(_pick('trailingPE'))
            info_out['forwardPE'] = _to_float_safe(_pick('forwardPE'))

            # Price / prev close: fallback to history if needed
            price = _to_float_safe(_pick('regularMarketPrice', 'currentPrice', 'price', 'lastPrice'))
            prev_close = _to_float_safe(_pick('previousClose', 'previous_close', 'regularMarketPreviousClose'))

            if price is None or prev_close is None:
                try:
                    hist = t.history(period='5d', interval='1d')
                    if hist is not None and not hist.empty:
                        last_row = hist.iloc[-1]
                        close = _to_float_safe(last_row.get('Close'))
                        if price is None:
                            price = close
                        if prev_close is None and len(hist) >= 2:
                            prev_row = hist.iloc[-2]
                            prev_close = _to_float_safe(prev_row.get('Close'))
                except Exception:
                    pass

            info_out['price'] = price
            info_out['previousClose'] = prev_close

            # change / change_pct
            change_amt = None
            change_pct = None
            if price is not None and prev_close is not None:
                try:
                    change_amt = float(price - prev_close)
                    change_pct = float(change_amt / prev_close) if prev_close != 0 else 0.0
                except Exception:
                    change_amt = None
                    change_pct = None

            # 52w high/low
            fifty_two_high = _to_float_safe(_pick('fiftyTwoWeekHigh', '52WeekHigh', 'fifty_two_week_high', '52w_high'))
            fifty_two_low = _to_float_safe(_pick('fiftyTwoWeekLow', '52WeekLow', 'fifty_two_week_low', '52w_low'))

            # fallback from 1y history
            if fifty_two_high is None or fifty_two_low is None:
                try:
                    hist_y = t.history(period='1y', interval='1d')
                    if hist_y is not None and not hist_y.empty:
                        highs = hist_y['High'].dropna()
                        lows = hist_y['Low'].dropna()
                        if fifty_two_high is None and not highs.empty:
                            fifty_two_high = float(highs.max())
                        if fifty_two_low is None and not lows.empty:
                            fifty_two_low = float(lows.min())
                except Exception:
                    pass

            info_out['fiftyTwoWeekHigh'] = fifty_two_high
            info_out['fiftyTwoWeekLow'] = fifty_two_low
            info_out['change'] = change_amt
            info_out['change_pct'] = change_pct

            # Financials
            info_out['pegRatio'] = _to_float_safe(_pick('pegRatio', 'forwardPEOverGrowth'))
            info_out['priceToSalesTrailing12Months'] = _to_float_safe(_pick('priceToSalesTrailing12Months', 'pToS', 'ps'))
            info_out['priceToBook'] = _to_float_safe(_pick('priceToBook', 'pToB', 'pb'))
            info_out['enterpriseToRevenue'] = _to_float_safe(_pick('enterpriseToRevenue', 'EVToRevenue'))
            info_out['enterpriseToEbitda'] = _to_float_safe(_pick('enterpriseToEbitda', 'EVToEbitda'))
            info_out['profitMargins'] = _to_float_safe(_pick('profitMargins', 'profitMargin'))
            info_out['returnOnAssets'] = _to_float_safe(_pick('returnOnAssets', 'ROA'))
            info_out['returnOnEquity'] = _to_float_safe(_pick('returnOnEquity', 'ROE'))
            info_out['totalRevenue'] = _to_float_safe(_pick('totalRevenue', 'revenue'))
            info_out['netIncomeToCommon'] = _to_float_safe(_pick('netIncomeToCommon', 'netIncome'))
            info_out['trailingEps'] = _to_float_safe(_pick('trailingEps', 'eps'))
            info_out['totalCash'] = _to_float_safe(_pick('totalCash', 'cash'))
            info_out['debtToEquity'] = _to_float_safe(_pick('debtToEquity', 'debtToEquityRatio'))
            info_out['freeCashflow'] = _to_float_safe(_pick('freeCashflow', 'fcf'))

            # verbatim extras
            for k in ['symbol', 'logo_url', 'website', 'industry', 'fullTimeEmployees']:
                v = info.get(k)
                if v is not None:
                    info_out[k] = v

            # successful candidate found — break out
            return info_out

        except Exception as e:
            last_exception = e
            logger.debug("get_stock_info try failed for %s => %s : %s", ticker_in, symbol_to_try, e)
            continue

    # No variant produced usable data — return minimal shape
    if last_exception:
        logger.debug("get_stock_info: all variants failed for %s: %s", ticker_in, last_exception)

    info_out.setdefault('price', None)
    info_out.setdefault('previousClose', None)
    info_out.setdefault('fiftyTwoWeekHigh', None)
    info_out.setdefault('fiftyTwoWeekLow', None)
    info_out.setdefault('change', None)
    info_out.setdefault('change_pct', None)
    info_out.setdefault('currency', 'USD')
    info_out.setdefault('shortName', ticker_in)
    return info_out


# ---------------------- Holdings / Transactions helpers ----------------------

def compute_holdings_from_transactions(transactions: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Compute holdings summary per ticker from transaction list using FIFO for sells.

    Keeps the original stored symbol as the key (so DB/CSV storage doesn't change),
    but attaches 'currency' to each holding using get_stock_info resolution (tries variants).
    """
    holdings: Dict[str, Dict[str, Any]] = {}
    lots: Dict[str, List[Dict[str, Any]]] = {}

    def _parse_date(dt_str: Any) -> datetime:
        if isinstance(dt_str, (datetime, date)):
            return datetime.combine(dt_str, datetime.min.time()) if isinstance(dt_str, date) and not isinstance(dt_str, datetime) else dt_str
        try:
            return datetime.strptime(str(dt_str), "%Y-%m-%d")
        except Exception:
            try:
                return datetime.fromisoformat(str(dt_str))
            except Exception:
                return datetime.utcnow()

    txs_sorted = sorted(transactions, key=lambda x: _parse_date(x.get('date') or x.get('transactionDate') or x.get('time') or datetime.utcnow()))

    for tx in txs_sorted:
        typ = (tx.get('type') or '').title()
        # keep the stored ticker key as-is (don't mutate user's stored symbol)
        symbol_key = (tx.get('stock') or tx.get('ticker') or '').upper()
        try:
            qty = int(tx.get('quantity') or 0)
        except Exception:
            qty = 0
        try:
            price = float(tx.get('price') or tx.get('amount') or 0.0)
        except Exception:
            price = 0.0

        if not symbol_key or qty == 0:
            continue

        if symbol_key not in holdings:
            holdings[symbol_key] = {
                'quantity': 0,
                'total_cost': 0.0,
                'avg_cost': 0.0,
                'first_buy_date': None,
                'realized_gain': 0.0,
                'unrealized_gain': 0.0,
                'currency': None,   # will fill below from get_stock_info
            }
            lots[symbol_key] = []

        if typ == 'Buy':
            lots[symbol_key].append({'qty': qty, 'price': price, 'date': tx.get('date')})
            holdings[symbol_key]['quantity'] += qty
            holdings[symbol_key]['total_cost'] += qty * price
            if not holdings[symbol_key]['first_buy_date']:
                holdings[symbol_key]['first_buy_date'] = tx.get('date')

        elif typ == 'Sell':
            proceeds = qty * price
            remaining = qty
            cost_removed = 0.0
            while remaining > 0 and lots[symbol_key]:
                lot = lots[symbol_key][0]
                lot_qty = lot['qty']
                take = min(remaining, lot_qty)
                cost_removed += take * lot['price']
                lot['qty'] -= take
                remaining -= take
                holdings[symbol_key]['quantity'] -= take
                holdings[symbol_key]['total_cost'] -= take * lot['price']
                if lot['qty'] == 0:
                    lots[symbol_key].pop(0)
            realized = proceeds - cost_removed
            holdings[symbol_key]['realized_gain'] += realized

        # update avg_cost safely
        q = holdings[symbol_key]['quantity']
        holdings[symbol_key]['avg_cost'] = (holdings[symbol_key]['total_cost'] / q) if q > 0 else 0.0

    # Compute unrealized gain and currency using get_stock_info
    for symbol_key, h in holdings.items():
        try:
            # Try to resolve with the stored key; get_stock_info will attempt .NS/.BO variants inside
            info = get_stock_info(symbol_key)
            price = _to_float_safe(info.get('price'))
            currency = info.get('currency') or None
            h['currency'] = currency
            if price is not None:
                h['unrealized_gain'] = (price * h['quantity']) - h['total_cost']
            else:
                h['unrealized_gain'] = 0.0
        except Exception:
            h['unrealized_gain'] = 0.0
            h['currency'] = h.get('currency') or None

    return holdings



# ---------------------- XIRR (portfolio IRR) ----------------------

def _xnpv(rate: float, cashflows: List[Tuple[datetime, float]]) -> float:
    """Net present value for uneven cashflows at given rate."""
    if rate <= -1.0:
        # avoid division by zero or negative rate causing issues
        rate = -0.9999999999
    t0 = cashflows[0][0]
    s = 0.0
    for (d, c) in cashflows:
        days = (d - t0).days
        s += c / ((1 + rate) ** (days / 365.0))
    return s


def _xirr_newton(cashflows: List[Tuple[datetime, float]], guess: float = 0.1, tol: float = 1e-6, maxiter: int = 100) -> Optional[float]:
    """Newton-Raphson method to solve for XIRR. Returns decimal (e.g., 0.12 == 12%)."""
    try:
        rate = guess
        for i in range(maxiter):
            # f(rate) and derivative approximation
            f = _xnpv(rate, cashflows)
            # derivative via small h
            h = 1e-6
            f1 = _xnpv(rate + h, cashflows)
            deriv = (f1 - f) / h
            if abs(deriv) < 1e-12:
                break
            new_rate = rate - f / deriv
            if abs(new_rate - rate) < tol:
                return new_rate
            rate = new_rate
        # fallback: try simple bracket search
        # return None if it didn't converge
        return rate
    except Exception:
        return None


def calculate_portfolio_xirr(transactions: List[Dict[str, Any]], fy_anchor_month: int = 4) -> float:
    """Compute portfolio XIRR using transactions and current market value as terminal inflow.

    - Buys are negative cashflows (money out), Sells are positive cashflows.
    - Terminal inflow is sum(current_price * quantity) at today.
    - Returns annualized decimal (e.g., 0.12 for 12%).
    """
    if not transactions:
        return 0.0

    cashflows: List[Tuple[datetime, float]] = []

    def _parse_date(dt_str: Any) -> datetime:
        if isinstance(dt_str, (datetime, date)):
            return datetime.combine(dt_str, datetime.min.time()) if isinstance(dt_str, date) and not isinstance(dt_str, datetime) else dt_str
        try:
            return datetime.strptime(str(dt_str), "%Y-%m-%d")
        except Exception:
            try:
                return datetime.fromisoformat(str(dt_str))
            except Exception:
                return datetime.utcnow()

    for tx in transactions:
        typ = (tx.get('type') or '').title()
        symbol = (tx.get('stock') or tx.get('ticker') or '').upper()
        try:
            qty = int(tx.get('quantity') or 0)
        except Exception:
            qty = 0
        try:
            price = float(tx.get('price') or tx.get('amount') or 0.0)
        except Exception:
            price = 0.0

        if qty == 0 or not symbol:
            continue

        dt = _parse_date(tx.get('date') or tx.get('transactionDate') or datetime.utcnow())
        cf = qty * price
        if typ == 'Buy':
            cashflows.append((dt, -cf))
        elif typ == 'Sell':
            cashflows.append((dt, cf))

    # Terminal value: compute current holdings and their market values
    holdings = compute_holdings_from_transactions(transactions)
    terminal_value = 0.0
    for symbol, h in holdings.items():
        try:
            info = get_stock_info(symbol)
            price = _to_float_safe(info.get('price'))
            if price is not None:
                terminal_value += price * h.get('quantity', 0)
        except Exception:
            continue

    today = datetime.utcnow()
    # add terminal cashflow at today as positive inflow
    if terminal_value != 0:
        cashflows.append((today, terminal_value))

    if not cashflows:
        return 0.0

    # ensure chronological
    cashflows = sorted(cashflows, key=lambda x: x[0])

    irr = _xirr_newton(cashflows, guess=0.05)
    try:
        if irr is None:
            return 0.0
        return float(irr)
    except Exception:
        return 0.0


# ---------------------- Capital gains breakdown ----------------------

def capital_gains_breakdown(transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Produce a simple capital gains breakdown per stock and summary.

    For realized gains we compute using FIFO matching sell lots to buys.
    For each sell, we classify short-term (< 365 days) or long-term (>=365 days).
    """
    if not transactions:
        return {'total_realized': 0.0, 'total_unrealized': 0.0, 'per_stock': {}}

    per_stock = {}

    # reuse compute_holdings to get current holdings + realized (but compute details separately)
    holdings = compute_holdings_from_transactions(transactions)

    # We'll reuse a FIFO mechanism similar to compute_holdings but keep track of realized details
    def _parse_date(dt_str: Any) -> datetime:
        if isinstance(dt_str, (datetime, date)):
            return datetime.combine(dt_str, datetime.min.time()) if isinstance(dt_str, date) and not isinstance(dt_str, datetime) else dt_str
        try:
            return datetime.strptime(str(dt_str), "%Y-%m-%d")
        except Exception:
            try:
                return datetime.fromisoformat(str(dt_str))
            except Exception:
                return datetime.utcnow()

    txs_sorted = sorted(transactions, key=lambda x: _parse_date(x.get('date') or x.get('transactionDate') or datetime.utcnow()))

    lots = {}
    totals = {'total_realized': 0.0, 'total_unrealized': 0.0}

    for tx in txs_sorted:
        typ = (tx.get('type') or '').title()
        symbol = (tx.get('stock') or tx.get('ticker') or '').upper()
        if not symbol:
            continue
        qty = int(tx.get('quantity') or 0)
        price = float(tx.get('price') or tx.get('amount') or 0.0)
        dt = _parse_date(tx.get('date') or tx.get('transactionDate') or datetime.utcnow())

        if symbol not in lots:
            lots[symbol] = []
            per_stock[symbol] = {'realized': 0.0, 'short_term': 0.0, 'long_term': 0.0, 'realized_trades': [], 'unrealized': 0.0}

        if typ == 'Buy':
            lots[symbol].append({'qty': qty, 'price': price, 'date': dt})

        elif typ == 'Sell':
            remaining = qty
            proceeds = qty * price
            cost_removed = 0.0
            realized_gain = 0.0
            # match FIFO
            while remaining > 0 and lots[symbol]:
                lot = lots[symbol][0]
                take = min(remaining, lot['qty'])
                cost_removed += take * lot['price']
                holding_period_days = (dt - lot['date']).days
                gain = take * price - take * lot['price']
                if holding_period_days >= 365:
                    per_stock[symbol]['long_term'] += gain
                else:
                    per_stock[symbol]['short_term'] += gain
                lot['qty'] -= take
                remaining -= take
                if lot['qty'] == 0:
                    lots[symbol].pop(0)
            realized_gain = proceeds - cost_removed
            per_stock[symbol]['realized'] += realized_gain
            per_stock[symbol]['realized_trades'].append({'date': dt.isoformat(), 'quantity': qty, 'proceeds': proceeds, 'cost_removed': cost_removed, 'gain': realized_gain})
            totals['total_realized'] += realized_gain

    # compute unrealized using current prices and the remaining lots
    for symbol, remaining_lots in lots.items():
        qty_remaining = sum([l['qty'] for l in remaining_lots])
        if qty_remaining <= 0:
            continue
        try:
            info = get_stock_info(symbol)
            price = _to_float_safe(info.get('price'))
            cost_basis = sum([l['qty'] * l['price'] for l in remaining_lots])
            if price is not None:
                unreal = qty_remaining * price - cost_basis
                per_stock[symbol]['unrealized'] = unreal
                totals['total_unrealized'] += unreal
        except Exception:
            per_stock[symbol]['unrealized'] = 0.0

    result = {'total_realized': totals['total_realized'], 'total_unrealized': totals['total_unrealized'], 'per_stock': per_stock}
    return result


# ---------------------- Sanitizer for JSON responses ----------------------

def _sanitize_obj(obj: Any) -> Any:
    """Recursively sanitize objects so they are JSON serializable and safe for frontends.

    - Decimal -> float
    - datetime/date -> ISO string
    - sets -> list
    - other mappings/list handled recursively
    """
    if obj is None:
        return None
    if isinstance(obj, Decimal):
        try:
            return float(obj)
        except Exception:
            return str(obj)
    if isinstance(obj, (int, float, str, bool)):
        return obj
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): _sanitize_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_sanitize_obj(v) for v in obj]
    # fallback
    try:
        return str(obj)
    except Exception:
        return None
