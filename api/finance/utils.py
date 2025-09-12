# api/finance/utils.py
import logging
from datetime import datetime, timedelta
from functools import lru_cache
from typing import List, Dict, Optional
import yfinance as yf
import math
from decimal import Decimal

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

def _to_native_number(v):
    """Convert Decimal/numpy/... to native float/int where reasonable."""
    try:
        if isinstance(v, Decimal):
            return float(v)
        # add other conversions if you use numpy: `import numpy as np` then `isinstance(v, np.generic)`
        return v
    except Exception:
        return None

def _is_bad_number(v):
    """Return True for NaN/Infinity or non-serializable numeric types."""
    try:
        if isinstance(v, (float,)):
            return math.isnan(v) or math.isinf(v)
        return False
    except Exception:
        return True

def _sanitize_obj(o, path=""):
    """
    Recursively sanitize: replace NaN/Inf with None (or 0.0 if you prefer numeric fallback).
    Also convert Decimal -> float, ensure only JSON-serializable types remain.
    """
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            new_path = f"{path}.{k}" if path else k
            out[k] = _sanitize_obj(v, new_path)
        return out
    elif isinstance(o, list):
        return [_sanitize_obj(item, f"{path}[]") for item in o]
    else:
        # convert Decimal -> float
        try:
            o = _to_native_number(o)
        except Exception:
            pass
        # handle floats
        if isinstance(o, float):
            if math.isnan(o) or math.isinf(o):
                logger.warning("Sanitizer replaced non-finite at %s (was %s)", path, o)
                return None   # use 0.0 if you prefer
            return o
        # if it's int/str/bool/None, pass through
        if isinstance(o, (int, str, bool)) or o is None:
            return o
        # fallback: try to coerce to str
        try:
            return str(o)
        except Exception:
            logger.warning("Sanitizer coerced unhandled type at %s to null", path)
            return None

# ----------------------
# Stock Info (cached)
# ----------------------
@lru_cache(maxsize=512)
def get_stock_info(ticker: str) -> dict:
    ticker = (ticker or "").upper()
    fallback = {
        "price": 0.0,
        "shortName": ticker,
        "name": ticker,
        "currency": "N/A",
        "exchange": "N/A",
        "sector": "N/A",
    }
    try:
        stock = yf.Ticker(ticker)
        info = stock.info or {}
        price = info.get("regularMarketPrice") or 0.0
        hist = stock.history(period="1d")
        if hist is not None and not hist.empty:
            try:
                price = float(hist["Close"].iloc[-1])
            except Exception:
                pass

        return {
            "price": price,
            "currency": info.get("currency", "N/A"),
            "exchange": info.get("exchange", "N/A"),
            "industry": info.get("industry", "N/A"),
            "sector": info.get("sector", "N/A"),
            "52w_high": info.get("fiftyTwoWeekHigh", info.get("52WeekHigh", price)),
            "52w_low": info.get("fiftyTwoWeekLow", info.get("52WeekLow", price)),
            "shortName": info.get("shortName", ticker),
            "longName": info.get("longName", ticker),
            "name": info.get("shortName") or info.get("longName") or ticker,
            "marketCap": info.get("marketCap", 0),
            "trailingPE": info.get("trailingPE", 0),
            "forwardPE": info.get("forwardPE", 0),
            "pegRatio": info.get("pegRatio", 0),
            "priceToSalesTrailing12Months": info.get("priceToSalesTrailing12Months", 0),
            "priceToBook": info.get("priceToBook", 0),
            "enterpriseToRevenue": info.get("enterpriseToRevenue", 0),
            "enterpriseToEbitda": info.get("enterpriseToEbitda", 0),
            "profitMargins": info.get("profitMargins", 0),
            "returnOnAssets": info.get("returnOnAssets", 0),
            "returnOnEquity": info.get("returnOnEquity", 0),
            "totalRevenue": info.get("totalRevenue", 0),
            "netIncomeToCommon": info.get("netIncomeToCommon", 0),
            "trailingEps": info.get("trailingEps", 0),
            "totalCash": info.get("totalCash", 0),
            "debtToEquity": info.get("debtToEquity", 0),
            "freeCashflow": info.get("freeCashflow", 0),
        }
    except Exception as e:
        logger.exception("Error fetching data for %s: %s", ticker, e)
        return fallback


# ----------------------
# XNPV / XIRR implementation
# ----------------------
def _xnpv(rate: float, cash_flows: List[float], dates: List[datetime]) -> float:
    if rate <= -1:
        return float("inf")
    t0 = dates[0]
    npv = 0.0
    for cf, d in zip(cash_flows, dates):
        days = (d - t0).days
        npv += cf / ((1.0 + rate) ** (days / 365.0))
    return npv


def _dxnpv(rate: float, cash_flows: List[float], dates: List[datetime]) -> float:
    if rate <= -1:
        return float("inf")
    t0 = dates[0]
    deriv = 0.0
    for cf, d in zip(cash_flows, dates):
        days = (d - t0).days
        power = (days / 365.0)
        deriv += -cf * power / ((1.0 + rate) ** (power + 1.0))
    return deriv


def xirr(cash_flows: List[float], dates: List[datetime], guess: float = 0.1, max_iters: int = 200) -> float:
    """
    Robust XIRR calculation that avoids NaN and returns 0 if calculation fails.
    """
    if not cash_flows or not dates or len(cash_flows) != len(dates):
        return 0.0

    # Ensure we have at least one negative and one positive cash flow
    if all(cf >= 0 for cf in cash_flows) or all(cf <= 0 for cf in cash_flows):
        logger.warning("XIRR requires at least one negative and one positive cash flow. Returning 0.")
        return 0.0

    try:
        rate = guess
        for _ in range(max_iters):
            f = _xnpv(rate, cash_flows, dates)
            df = _dxnpv(rate, cash_flows, dates)
            if abs(df) < 1e-12:
                break
            new_rate = rate - f / df
            if math.isnan(new_rate) or math.isinf(new_rate):
                return 0.0
            if abs(new_rate - rate) < 1e-9:
                return new_rate
            rate = new_rate
        return rate
    except Exception:
        logger.exception("XIRR calculation failed")
        return 0.0


# ----------------------
# Holdings / Lot tracking / Gains
# ----------------------
def compute_holdings_from_transactions(transactions: List[Dict]) -> Dict[str, Dict]:
    holdings: Dict[str, Dict] = {}
    lots: Dict[str, List[Dict]] = {}
    realized_gains: Dict[str, float] = {}
    txs = sorted(transactions, key=lambda x: x.get("date", ""))

    for tx in txs:
        stock = (tx.get("stock") or "").upper()
        tx_type = (tx.get("type") or "").capitalize()
        try:
            qty = int(tx.get("quantity", 0))
            price = float(tx.get("price", 0.0))
            date_str = tx.get("date")
            date = datetime.strptime(date_str, "%Y-%m-%d") if date_str else None
        except Exception:
            logger.exception("Skipping malformed transaction: %s", tx)
            continue

        if stock not in holdings:
            holdings[stock] = {
                "stock": stock,
                "quantity": 0,
                "total_cost": 0.0,
                "avg_cost": 0.0,
                "first_buy_date": date_str,
                "realized_gain": 0.0,
                "unrealized_gain": 0.0,
                "lots": [],
            }
            lots[stock] = []
            realized_gains[stock] = 0.0

        if tx_type == "Buy":
            lots[stock].append({"quantity": qty, "price": price, "date": date})
            holdings[stock]["quantity"] += qty
            holdings[stock]["total_cost"] += qty * price
            holdings[stock]["first_buy_date"] = min(
                holdings[stock]["first_buy_date"], date_str
            ) if holdings[stock]["first_buy_date"] else date_str
        elif tx_type == "Sell":
            sell_qty = qty
            cost_removed = 0.0
            proceeds = qty * price
            while sell_qty > 0 and lots[stock]:
                lot = lots[stock][0]
                lot_qty = int(lot["quantity"])
                lot_price = float(lot["price"])
                matched_qty = min(sell_qty, lot_qty)
                cost_removed += matched_qty * lot_price
                if matched_qty >= lot_qty:
                    lots[stock].pop(0)
                else:
                    lot["quantity"] = lot_qty - matched_qty
                sell_qty -= matched_qty
            realized = proceeds - cost_removed
            realized_gains[stock] += realized
            holdings[stock]["realized_gain"] = realized_gains[stock]
            holdings[stock]["quantity"] = max(0, holdings[stock]["quantity"] - qty)
            holdings[stock]["total_cost"] = max(0.0, holdings[stock]["total_cost"] - cost_removed)

    for stock, h in holdings.items():
        qty = h["quantity"]
        total_cost = h["total_cost"]
        h["avg_cost"] = (total_cost / qty) if qty > 0 else 0.0
        try:
            market_price = float(get_stock_info(stock).get("price", 0.0))
        except Exception:
            market_price = 0.0
        h["unrealized_gain"] = market_price * qty - total_cost
        h["lots"] = lots.get(stock, [])

    return holdings


# ----------------------
# Capital Gains Breakdown
# ----------------------
def capital_gains_breakdown(transactions: List[Dict], st_threshold_days: int = 365) -> Dict:
    per_stock = {}
    totals = {"STCG": 0.0, "LTCG": 0.0}
    buy_lots: Dict[str, List[Dict]] = {}
    txs = sorted(transactions, key=lambda x: x.get("date", ""))

    for tx in txs:
        stock = (tx.get("stock") or "").upper()
        tx_type = (tx.get("type") or "").capitalize()
        try:
            qty = int(tx.get("quantity", 0))
            price = float(tx.get("price", 0.0))
            date_str = tx.get("date")
            date = datetime.strptime(date_str, "%Y-%m-%d") if date_str else None
        except Exception:
            logger.exception("Skipping malformed transaction in capital gains calc: %s", tx)
            continue

        if stock not in per_stock:
            per_stock[stock] = {"STCG": 0.0, "LTCG": 0.0, "details": []}
        if stock not in buy_lots:
            buy_lots[stock] = []

        if tx_type == "Buy":
            buy_lots[stock].append({"quantity": qty, "price": price, "date": date})
        elif tx_type == "Sell":
            sell_qty = qty
            sell_price = price
            sell_date = date
            while sell_qty > 0 and buy_lots[stock]:
                lot = buy_lots[stock][0]
                lot_qty = int(lot["quantity"])
                lot_price = float(lot["price"])
                lot_date = lot["date"]
                matched_qty = min(sell_qty, lot_qty)
                cost_basis = matched_qty * lot_price
                proceeds = matched_qty * sell_price
                gain = proceeds - cost_basis
                holding_days = (sell_date - lot_date).days if lot_date and sell_date else st_threshold_days
                gain_type = "STCG" if holding_days < st_threshold_days else "LTCG"
                per_stock[stock][gain_type] += gain
                totals[gain_type] += gain
                per_stock[stock]["details"].append({
                    "sold_qty": matched_qty,
                    "buy_price": lot_price,
                    "sell_price": sell_price,
                    "gain": gain,
                    "type": gain_type,
                    "buy_date": lot_date.isoformat() if lot_date else None,
                    "sell_date": sell_date.isoformat() if sell_date else None,
                    "holding_days": holding_days,
                })
                if matched_qty >= lot_qty:
                    buy_lots[stock].pop(0)
                else:
                    lot["quantity"] = lot_qty - matched_qty
                sell_qty -= matched_qty
            if sell_qty > 0:
                unmatched_proceeds = sell_qty * sell_price
                per_stock[stock]["STCG"] += unmatched_proceeds
                totals["STCG"] += unmatched_proceeds
                per_stock[stock]["details"].append({
                    "sold_qty": sell_qty,
                    "buy_price": None,
                    "sell_price": sell_price,
                    "gain": unmatched_proceeds,
                    "type": "STCG",
                    "buy_date": None,
                    "sell_date": sell_date.isoformat() if sell_date else None,
                    "holding_days": None,
                })

    # Ensure no NaNs
    for stock, data in per_stock.items():
        for key in ["STCG", "LTCG"]:
            if data[key] is None or math.isnan(data[key]):
                data[key] = 0.0
    for key in ["STCG", "LTCG"]:
        if totals[key] is None or math.isnan(totals[key]):
            totals[key] = 0.0

    return {"per_stock": per_stock, "totals": totals}


# ----------------------
# Portfolio XIRR
# ----------------------
def calculate_portfolio_xirr(transactions: List[Dict], fy_anchor_month: int = 4) -> float:
    if not transactions:
        return 0.0

    today = datetime.utcnow()
    fy_start = datetime(today.year, fy_anchor_month, 1) if today.month >= fy_anchor_month else datetime(today.year - 1, fy_anchor_month, 1)

    cash_flows: List[float] = []
    dates: List[datetime] = []

    for tx in transactions:
        try:
            date_str = tx.get("date")
            if not date_str:
                continue
            date = datetime.strptime(date_str, "%Y-%m-%d")
            if date < fy_start:
                continue
            qty = float(tx.get("quantity", 0))
            price = float(tx.get("price", 0.0))
            amount = qty * price
            if (tx.get("type") or "").lower() == "buy":
                amount = -amount
            cash_flows.append(amount)
            dates.append(date)
        except Exception:
            logger.exception("Skipping malformed tx for XIRR: %s", tx)
            continue

    holdings = compute_holdings_from_transactions(transactions)
    portfolio_value = sum(
        float(h.get("quantity", 0)) * float(get_stock_info(s).get("price", 0.0))
        for s, h in holdings.items()
    )

    if portfolio_value > 0:
        cash_flows.append(portfolio_value)
        dates.append(today)

    # Remove zero cash flows to avoid division by zero
    non_zero_flows = [(cf, dt) for cf, dt in zip(cash_flows, dates) if cf != 0.0]
    if len(non_zero_flows) < 2:
        return 0.0

    sorted_flows = sorted(non_zero_flows, key=lambda x: x[1])
    sorted_dates, sorted_cash_flows = zip(*sorted_flows)

    rate = xirr(list(sorted_cash_flows), list(sorted_dates))
    if math.isnan(rate) or math.isinf(rate):
        return 0.0
    return rate * 100.0


# ----------------------
# Daily P/L, Gainers, Losers
# ----------------------
def calculate_daily_pnl(transactions: List[Dict]) -> Dict[str, Dict]:
    holdings = compute_holdings_from_transactions(transactions)
    result = {"stocks": {}, "gainers": [], "losers": []}

    for stock, h in holdings.items():
        qty = h["quantity"]
        avg_cost = h["avg_cost"]
        current_price = float(get_stock_info(stock).get("price", 0.0))
        unrealized = qty * (current_price - avg_cost)
        result["stocks"][stock] = {
            "quantity": qty,
            "avg_cost": avg_cost,
            "current_price": current_price,
            "unrealized_gain": unrealized,
        }

    sorted_stocks = sorted(result["stocks"].items(), key=lambda x: x[1]["unrealized_gain"], reverse=True)
    result["gainers"] = sorted_stocks[:5]
    result["losers"] = sorted_stocks[-5:][::-1]

    return result
