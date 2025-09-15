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


# ----------------------
# Helper functions
# ----------------------
def _to_native_number(v):
    """Convert Decimal/numpy/... to native float/int where reasonable."""
    try:
        if isinstance(v, Decimal):
            return float(v)
        return v
    except Exception:
        return None


def _is_bad_number(v):
    """Return True for NaN/Infinity or non-serializable numeric types."""
    try:
        if isinstance(v, float):
            return math.isnan(v) or math.isinf(v)
        return False
    except Exception:
        return True


def _sanitize_obj(o, path=""):
    """Recursively sanitize: replace NaN/Inf with None, convert Decimal -> float."""
    if isinstance(o, dict):
        return {k: _sanitize_obj(v, f"{path}.{k}" if path else k) for k, v in o.items()}
    elif isinstance(o, list):
        return [_sanitize_obj(item, f"{path}[]") for item in o]
    else:
        o = _to_native_number(o)
        if isinstance(o, float) and (_is_bad_number(o)):
            logger.warning("Sanitizer replaced non-finite at %s (was %s)", path, o)
            return 0.0
        if isinstance(o, (int, str, bool)) or o is None:
            return o
        try:
            return str(o)
        except Exception:
            logger.warning("Sanitizer coerced unhandled type at %s to null", path)
            return None


def _ensure_date(d) -> Optional[datetime]:
    """Ensure we return a datetime when possible."""
    if d is None:
        return None
    if isinstance(d, datetime):
        return d
    if isinstance(d, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(d, fmt)
            except Exception:
                continue
        try:
            return datetime.fromisoformat(d)
        except Exception:
            return None
    return None


# ----------------------
# Stock Info (cached)
# ----------------------
@lru_cache(maxsize=512)
def get_stock_info(ticker: str) -> dict:
    ticker = (ticker or "").upper()
    fallback = {
        "price": 0.0,
        "prev_close": 0.0,
        "currency": "N/A",
        "exchange": "N/A",
        "industry": "N/A",
        "sector": "N/A",
        "52w_high": 0.0,
        "52w_low": 0.0,
        "shortName": ticker,
        "longName": ticker,
        "name": ticker,
        "marketCap": 0.0,
        "trailingPE": 0.0,
        "forwardPE": 0.0,
        "pegRatio": 0.0,
        "priceToSalesTrailing12Months": 0.0,
        "priceToBook": 0.0,
        "enterpriseToRevenue": 0.0,
        "enterpriseToEbitda": 0.0,
        "profitMargins": 0.0,
        "returnOnAssets": 0.0,
        "returnOnEquity": 0.0,
        "totalRevenue": 0.0,
        "netIncomeToCommon": 0.0,
        "trailingEps": 0.0,
        "totalCash": 0.0,
        "debtToEquity": 0.0,
        "freeCashflow": 0.0,
    }
    try:
        stock = yf.Ticker(ticker)
        info = stock.info or {}

        price = info.get("regularMarketPrice") or 0.0
        prev_close = info.get("regularMarketPreviousClose") or price

        try:
            hist = stock.history(period="1d")
            if hist is not None and not getattr(hist, "empty", True):
                price = float(hist["Close"].iloc[-1])
        except Exception:
            logger.debug("yfinance history failed for %s", ticker)

        return {
            **fallback,
            "price": _to_native_number(price) or 0.0,
            "prev_close": _to_native_number(prev_close) or 0.0,
            "currency": info.get("currency", "N/A"),
            "exchange": info.get("exchange", "N/A"),
            "industry": info.get("industry", "N/A"),
            "sector": info.get("sector", "N/A"),
            "52w_high": _to_native_number(info.get("fiftyTwoWeekHigh") or info.get("52WeekHigh") or price) or 0.0,
            "52w_low": _to_native_number(info.get("fiftyTwoWeekLow") or info.get("52WeekLow") or price) or 0.0,
            "shortName": info.get("shortName", ticker),
            "longName": info.get("longName", ticker),
            "name": info.get("shortName") or info.get("longName") or ticker,
            "marketCap": _to_native_number(info.get("marketCap")) or 0.0,
            "trailingPE": _to_native_number(info.get("trailingPE")) or 0.0,
            "forwardPE": _to_native_number(info.get("forwardPE")) or 0.0,
            "pegRatio": _to_native_number(info.get("pegRatio")) or 0.0,
            "priceToSalesTrailing12Months": _to_native_number(info.get("priceToSalesTrailing12Months")) or 0.0,
            "priceToBook": _to_native_number(info.get("priceToBook")) or 0.0,
            "enterpriseToRevenue": _to_native_number(info.get("enterpriseToRevenue")) or 0.0,
            "enterpriseToEbitda": _to_native_number(info.get("enterpriseToEbitda")) or 0.0,
            "profitMargins": _to_native_number(info.get("profitMargins")) or 0.0,
            "returnOnAssets": _to_native_number(info.get("returnOnAssets")) or 0.0,
            "returnOnEquity": _to_native_number(info.get("returnOnEquity")) or 0.0,
            "totalRevenue": _to_native_number(info.get("totalRevenue")) or 0.0,
            "netIncomeToCommon": _to_native_number(info.get("netIncomeToCommon")) or 0.0,
            "trailingEps": _to_native_number(info.get("trailingEps")) or 0.0,
            "totalCash": _to_native_number(info.get("totalCash")) or 0.0,
            "debtToEquity": _to_native_number(info.get("debtToEquity")) or 0.0,
            "freeCashflow": _to_native_number(info.get("freeCashflow")) or 0.0,
        }
    except Exception as e:
        logger.exception("Error fetching data for %s: %s", ticker, e)
        return fallback

# ----------------------
# XNPV / XIRR
# ----------------------
def _xnpv(rate: float, cash_flows: List[float], dates: List[datetime]) -> float:
    if rate <= -1:
        return float("inf")
    t0 = dates[0]
    npv = 0.0
    for cf, d in zip(cash_flows, dates):
        if not isinstance(d, datetime):
            d = _ensure_date(d)
            if d is None:
                continue
        npv += cf / ((1.0 + rate) ** ((d - t0).days / 365.0))
    return npv


def _dxnpv(rate: float, cash_flows: List[float], dates: List[datetime]) -> float:
    if rate <= -1:
        return float("inf")
    t0 = dates[0]
    deriv = 0.0
    for cf, d in zip(cash_flows, dates):
        if not isinstance(d, datetime):
            d = _ensure_date(d)
            if d is None:
                continue
        power = (d - t0).days / 365.0
        deriv += -cf * power / ((1.0 + rate) ** (power + 1))
    return deriv


def xirr(cash_flows: List[float], dates: List[datetime], guess: float = 0.1, max_iters: int = 200) -> float:
    if not cash_flows or not dates or len(cash_flows) != len(dates):
        return 0.0
    dates = [_ensure_date(d) for d in dates]
    if any(d is None for d in dates):
        logger.warning("xirr received invalid dates; aborting")
        return 0.0
    if all(cf >= 0 for cf in cash_flows) or all(cf <= 0 for cf in cash_flows):
        logger.warning("XIRR requires at least one negative and one positive cash flow. Returning 0.")
        return 0.0

    rate = guess
    try:
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
# Holdings / Lots / Gains
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
            date = _ensure_date(date_str)
        except Exception:
            logger.exception("Skipping malformed transaction: %s", tx)
            continue

        if stock not in holdings:
            holdings[stock] = {
                "stock": stock,
                "quantity": 0,
                "total_cost": 0.0,
                "avg_cost": 0.0,
                "first_buy_date": date_str if date_str else None,
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
            if date:
                current_first = holdings[stock]["first_buy_date"]
                try:
                    if current_first:
                        cfd = _ensure_date(current_first)
                        if cfd is None or date < cfd:
                            holdings[stock]["first_buy_date"] = date.date().isoformat()
                    else:
                        holdings[stock]["first_buy_date"] = date.date().isoformat()
                except Exception:
                    holdings[stock]["first_buy_date"] = date.date().isoformat()
        elif tx_type == "Sell":
            sell_qty = qty
            cost_removed = 0.0
            proceeds = qty * price
            while sell_qty > 0 and lots[stock]:
                lot = lots[stock][0]
                lot_qty = int(lot.get("quantity", 0))
                lot_price = float(lot.get("price", 0.0))
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
        serial_lots = []
        for lot in lots.get(stock, []):
            ld = lot.get("date")
            serial_lots.append({
                "quantity": int(lot.get("quantity", 0)),
                "price": _to_native_number(lot.get("price", 0.0)),
                "date": ld.date().isoformat() if isinstance(ld, datetime) else (ld if ld else None),
            })
        h["lots"] = serial_lots

    return holdings


# ----------------------
# Capital Gains
# ----------------------
# api/finance/utils.py (capital_gains_breakdown function)
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
            date = _ensure_date(date_str)
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
                lot_qty = int(lot.get("quantity", 0))
                lot_price = float(lot.get("price", 0.0))
                lot_date = lot.get("date")
                matched_qty = min(sell_qty, lot_qty)
                cost_basis = matched_qty * lot_price
                proceeds = matched_qty * sell_price
                gain = proceeds - cost_basis
                
                # Fix: Use proper field names (STCG/LTCG instead of stcg/ltcg)
                if isinstance(sell_date, datetime) and isinstance(lot_date, datetime):
                    holding_days = (sell_date - lot_date).days
                    gain_type = "STCG" if holding_days < st_threshold_days else "LTCG"
                else:
                    holding_days = None
                    gain_type = "STCG"
                
                per_stock[stock][gain_type] += gain
                totals[gain_type] += gain
                
                per_stock[stock]["details"].append({
                    "sold_qty": matched_qty,
                    "buy_price": lot_price,
                    "sell_price": sell_price,
                    "gain": gain,
                    "type": gain_type,
                    "buy_date": lot_date.date().isoformat() if isinstance(lot_date, datetime) else None,
                    "sell_date": sell_date.date().isoformat() if isinstance(sell_date, datetime) else None,
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
                    "sell_date": sell_date.date().isoformat() if isinstance(sell_date, datetime) else None,
                    "holding_days": None,
                })

    return {"per_stock": per_stock, "totals": totals}


# ----------------------
# Portfolio Daily P/L & Summary
# ----------------------
def calculate_daily_pnl(transactions: List[Dict]) -> Dict[str, Dict]:
    holdings = compute_holdings_from_transactions(transactions)
    result = {"stocks": {}, "top_daily_gainers": [], "top_daily_losers": [], "top_alltime_gainers": [], "top_alltime_losers": []}

    for stock, h in holdings.items():
        qty = h["quantity"]
        avg_cost = h["avg_cost"]
        info = get_stock_info(stock)
        current_price = float(info.get("price", 0.0))
        prev_close = float(info.get("prev_close", 0.0))
        unrealized = qty * (current_price - avg_cost)
        day_change = current_price - prev_close
        daily_pnl = qty * day_change
        result["stocks"][stock] = {
            "stock": stock,
            "quantity": qty,
            "avg_cost": avg_cost,
            "current_price": current_price,
            "prev_close": prev_close,
            "day_change": day_change,
            "daily_pnl": daily_pnl,
            "52w_high": float(info.get("52w_high", 0.0)),
            "52w_low": float(info.get("52w_low", 0.0)),
            "unrealized_gain": unrealized,
        }

    # Top 5 daily
    sorted_daily = sorted(result["stocks"].values(), key=lambda x: x["daily_pnl"], reverse=True)
    result["top_daily_gainers"] = sorted_daily[:5]
    result["top_daily_losers"] = sorted_daily[-5:][::-1]

    # Top all-time
    sorted_alltime = sorted(result["stocks"].values(), key=lambda x: x["unrealized_gain"], reverse=True)
    result["top_alltime_gainers"] = sorted_alltime[:5]
    result["top_alltime_losers"] = sorted_alltime[-5:][::-1]

    return result


# ----------------------
# Portfolio XIRR
# ----------------------
def calculate_portfolio_xirr(transactions: List[Dict], fy_anchor_month: int = 4) -> float:
    if not transactions:
        return 0.0
    today = datetime.utcnow()
    fy_start = datetime(today.year, fy_anchor_month, 1) if today.month >= fy_anchor_month else datetime(today.year - 1, fy_anchor_month, 1)

    cash_flows, dates = [], []
    for tx in transactions:
        date = _ensure_date(tx.get("date"))
        if date is None or date < fy_start:
            continue
        amt = float(tx.get("quantity", 0)) * float(tx.get("price", 0.0))
        if (tx.get("type") or "").capitalize() == "Buy":
            amt = -amt
        cash_flows.append(amt)
        dates.append(date)

    if not cash_flows or not dates:
        return 0.0

    return xirr(cash_flows, dates)
