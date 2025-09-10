# api/finance/utils.py
import logging
from datetime import datetime, timedelta
import yfinance as yf
from functools import lru_cache
from typing import List, Dict, Tuple, Optional

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# ----------------------
# Stock Info (cached)
# ----------------------
@lru_cache(maxsize=512)
def get_stock_info(ticker: str) -> dict:
    """
    Fetch normalized stock info and price.
    Uses caching to reduce Yahoo Finance API calls.
    """
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

        # Prefer history Close, fallback to regularMarketPrice
        price = info.get("regularMarketPrice", 0.0) or 0.0
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
    if not cash_flows or not dates or len(cash_flows) != len(dates):
        return 0.0
    try:
        rate = guess
        for i in range(max_iters):
            f = _xnpv(rate, cash_flows, dates)
            df = _dxnpv(rate, cash_flows, dates)
            if abs(df) < 1e-12:
                break
            new_rate = rate - f / df
            if abs(new_rate - rate) < 1e-9:
                return new_rate
            rate = new_rate
        lower, upper = -0.9999, 10.0
        fl, fu = _xnpv(lower, cash_flows, dates), _xnpv(upper, cash_flows, dates)
        if fl * fu > 0:
            return rate
        for _ in range(100):
            mid = (lower + upper) / 2.0
            fm = _xnpv(mid, cash_flows, dates)
            if abs(fm) < 1e-9:
                return mid
            if fl * fm < 0:
                upper = mid
                fu = fm
            else:
                lower = mid
                fl = fm
        return (lower + upper) / 2.0
    except Exception as e:
        logger.exception("XIRR calculation failed: %s", e)
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
        try:
            stock = (tx.get("stock") or "").upper()
            tx_type = (tx.get("type") or "").capitalize()
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
                if lot_qty <= sell_qty:
                    cost_removed += lot_qty * lot_price
                    sell_qty -= lot_qty
                    lots[stock].pop(0)
                else:
                    cost_removed += sell_qty * lot_price
                    lot["quantity"] = lot_qty - sell_qty
                    sell_qty = 0
            realized = proceeds - cost_removed
            realized_gains[stock] = realized_gains.get(stock, 0.0) + realized
            holdings[stock]["realized_gain"] = realized_gains[stock]
            holdings[stock]["quantity"] = max(0, holdings[stock]["quantity"] - qty)
            holdings[stock]["total_cost"] = max(0.0, holdings[stock]["total_cost"] - cost_removed)

    for stock, h in list(holdings.items()):
        qty = h["quantity"]
        total_cost = h["total_cost"]
        h["avg_cost"] = (total_cost / qty) if qty > 0 else 0.0
        try:
            market_price = float(get_stock_info(stock).get("price", 0.0) or 0.0)
        except Exception:
            market_price = 0.0
        market_value = market_price * qty
        h["unrealized_gain"] = market_value - total_cost
        h["lots"] = lots.get(stock, [])

    return holdings

# ----------------------
# Capital Gains Breakdown (STCG/LTCG)
# ----------------------
def capital_gains_breakdown(transactions: List[Dict], st_threshold_days: int = 365) -> Dict:
    per_stock = {}
    totals = {"STCG": 0.0, "LTCG": 0.0}
    buy_lots: Dict[str, List[Dict]] = {}
    txs = sorted(transactions, key=lambda x: x.get("date", ""))

    for tx in txs:
        try:
            stock = (tx.get("stock") or "").upper()
            tx_type = (tx.get("type") or "").capitalize()
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

    return {"per_stock": per_stock, "totals": totals}

# ----------------------
# Portfolio XIRR (FY-aware)
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
        float(h.get("quantity", 0)) * float(get_stock_info(s).get("price", 0.0) or 0.0)
        for s, h in holdings.items()
    )

    cash_flows.append(portfolio_value)
    dates.append(today)

    if len(cash_flows) <= 1:
        return 0.0
    combined = sorted(zip(dates, cash_flows), key=lambda x: x[0])
    dates_sorted, flows_sorted = zip(*combined)
    try:
        rate = xirr(list(flows_sorted), list(dates_sorted))
        return rate * 100.0
    except Exception:
        logger.exception("Failed compute portfolio XIRR")
        return 0.0

# ----------------------
# Daily P/L, Gainers, Losers
# ----------------------
def calculate_daily_pnl(transactions: List[Dict]) -> Dict[str, Dict]:
    """
    Returns per-stock daily P/L summary and top gainers/losers.
    """
    holdings = compute_holdings_from_transactions(transactions)
    result = {"stocks": {}, "gainers": [], "losers": []}

    for stock, h in holdings.items():
        qty = h["quantity"]
        avg_cost = h["avg_cost"]
        try:
            current_price = float(get_stock_info(stock).get("price", 0.0))
        except Exception:
            current_price = 0.0
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

# ----------------------
# Convenience wrappers
# ----------------------
def calculate_portfolio_irr(transactions: List[Dict]) -> float:
    return calculate_portfolio_xirr(transactions)

def calculate_realized_and_initial_investment(transactions: List[Dict]):
    lots: Dict[str, List[Dict]] = {}
    realized_gains: Dict[str, float] = {}
    initial_investment: Dict[str, float] = {}

    for tx in sorted(transactions, key=lambda x: x.get("date", "")):
        try:
            stock = (tx.get("stock") or "").upper()
            tx_type = (tx.get("type") or "").capitalize()
            qty = int(tx.get("quantity", 0))
            price = float(tx.get("price", 0.0))
        except Exception:
            logger.exception("Skipping malformed tx in realized calc: %s", tx)
            continue

        lots.setdefault(stock, [])
        realized_gains.setdefault(stock, 0.0)
        initial_investment.setdefault(stock, 0.0)

        if tx_type == "Buy":
            lots[stock].append({"quantity": qty, "price": price})
            initial_investment[stock] += qty * price
        elif tx_type == "Sell":
            sell_qty = qty
            cost_removed = 0.0
            if not lots[stock]:
                realized_gains[stock] += qty * price
                continue
            while sell_qty > 0 and lots[stock]:
                lot = lots[stock][0]
                lot_qty = int(lot["quantity"])
                lot_price = float(lot["price"])
                if lot_qty <= sell_qty:
                    cost_removed += lot_qty * lot_price
                    sell_qty -= lot_qty
                    lots[stock].pop(0)
                else:
                    cost_removed += sell_qty * lot_price
                    lot["quantity"] = lot_qty - sell_qty
                    sell_qty = 0
            proceeds = qty * price
            realized_gains[stock] += proceeds - cost_removed

    remaining_qty = {stock: sum(int(l["quantity"]) for l in stock_lots) for stock, stock_lots in lots.items()}
    remaining_cost_basis = {stock: sum(int(l["quantity"]) * float(l["price"]) for l in stock_lots) for stock, stock_lots in lots.items()}

    return realized_gains, initial_investment, remaining_cost_basis, remaining_qty
