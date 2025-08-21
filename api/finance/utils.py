# api/finance/utils.py
import logging
from datetime import datetime
import yfinance as yf
from functools import lru_cache

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


@lru_cache(maxsize=512)
def get_stock_info(ticker):
    """
    Fetch normalized stock info and price.
    Uses caching to reduce Yahoo Finance API calls.
    """
    ticker = ticker.upper()
    fallback = {'price': 0.0, 'shortName': ticker, 'name': ticker,
                'currency': 'N/A', 'exchange': 'N/A', 'sector': 'N/A'}
    try:
        stock = yf.Ticker(ticker)
        info = stock.info or {}
        # Use regularMarketPrice if history is empty
        price = info.get('regularMarketPrice', 0.0)
        hist = stock.history(period="1d")
        if not hist.empty:
            price = float(hist['Close'].iloc[-1])
        return {
            'price': price,
            'currency': info.get('currency', 'N/A'),
            'exchange': info.get('exchange', 'N/A'),
            'industry': info.get('industry', 'N/A'),
            'sector': info.get('sector', 'N/A'),
            '52w_high': info.get('fiftyTwoWeekHigh', info.get('52WeekHigh', price)),
            '52w_low': info.get('fiftyTwoWeekLow', info.get('52WeekLow', price)),
            'shortName': info.get('shortName', ticker),
            'longName': info.get('longName', ticker),
            'name': info.get('shortName') or info.get('longName') or ticker,
            'marketCap': info.get('marketCap', 0),
            'trailingPE': info.get('trailingPE', 0),
            'forwardPE': info.get('forwardPE', 0),
            'pegRatio': info.get('pegRatio', 0),
            'priceToSalesTrailing12Months': info.get('priceToSalesTrailing12Months', 0),
            'priceToBook': info.get('priceToBook', 0),
            'enterpriseToRevenue': info.get('enterpriseToRevenue', 0),
            'enterpriseToEbitda': info.get('enterpriseToEbitda', 0),
            'profitMargins': info.get('profitMargins', 0),
            'returnOnAssets': info.get('returnOnAssets', 0),
            'returnOnEquity': info.get('returnOnEquity', 0),
            'totalRevenue': info.get('totalRevenue', 0),
            'netIncomeToCommon': info.get('netIncomeToCommon', 0),
            'trailingEps': info.get('trailingEps', 0),
            'totalCash': info.get('totalCash', 0),
            'debtToEquity': info.get('debtToEquity', 0),
            'freeCashflow': info.get('freeCashflow', 0)
        }
    except Exception as e:
        logger.exception("Error fetching data for %s: %s", ticker, e)
        return fallback


def calculate_portfolio_irr(transactions):
    """
    Approximates IRR using annualized return from buy/sell cash flows.
    """
    cash_flows, dates = [], []
    for tx in transactions:
        try:
            amount = tx['quantity'] * tx['price']
            if tx['type'].lower() == 'buy':
                amount = -amount
            cash_flows.append(amount)
            dates.append(datetime.strptime(tx['date'], '%Y-%m-%d'))
        except Exception:
            continue

    if not cash_flows or not dates:
        return 0

    try:
        total_investment = sum(cf for cf in cash_flows if cf < 0)
        total_return = sum(cf for cf in cash_flows if cf > 0)
        days_held = max(1, (max(dates) - min(dates)).days)
        if total_investment == 0:
            return 0
        base = total_return / abs(total_investment)
        if base <= 0:
            return (base - 1) * 100
        annualized_return = ((1 + base) ** (365.0 / days_held) - 1) * 100
        return annualized_return
    except Exception:
        logger.exception("Error calculating IRR")
        return 0


def calculate_realized_and_initial_investment(transactions):
    """
    Returns:
        realized_gains, initial_investment, remaining_cost_basis, remaining_qty
    """
    lots, realized_gains, initial_investment = {}, {}, {}
    for tx in sorted(transactions, key=lambda x: x['date']):
        stock = tx['stock'].upper()
        qty, price, type_ = int(tx['quantity']), float(tx['price']), tx['type']
        lots.setdefault(stock, [])
        realized_gains.setdefault(stock, 0.0)
        initial_investment.setdefault(stock, 0.0)
        if type_ == 'Buy':
            lots[stock].append({'quantity': qty, 'price': price})
            initial_investment[stock] += qty * price
        elif type_ == 'Sell':
            sell_qty, sell_proceeds, cost_removed = qty, qty * price, 0.0
            if not lots[stock]:
                raise ValueError(f"No lots to sell for {stock}")
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
                raise ValueError(f"Selling more than held for {stock}")
            realized_gains[stock] += sell_proceeds - cost_removed

    remaining_qty, remaining_cost_basis = {}, {}
    for stock, stock_lots in lots.items():
        qty = sum(l['quantity'] for l in stock_lots)
        cost = sum(l['quantity'] * l['price'] for l in stock_lots)
        remaining_qty[stock] = qty
        remaining_cost_basis[stock] = cost

    return realized_gains, initial_investment, remaining_cost_basis, remaining_qty


def compute_holdings_from_transactions(transactions):
    """
    Computes current holdings with avg_cost and realized_gain
    """
    holdings, lots, realized_gains = {}, {}, {}
    for tx in sorted(transactions, key=lambda x: x['date']):
        stock = tx['stock'].upper()
        qty, price, date, type_ = int(tx['quantity']), float(tx['price']), tx['date'], tx['type']
        if stock not in holdings:
            holdings[stock] = {'stock': stock, 'quantity': 0, 'total_cost': 0.0, 'first_buy_date': date}
            lots[stock] = []
            realized_gains[stock] = 0.0

        if type_ == 'Buy':
            lots[stock].append({'quantity': qty, 'price': price})
            holdings[stock]['quantity'] += qty
            holdings[stock]['total_cost'] += qty * price
            holdings[stock]['first_buy_date'] = min(holdings[stock]['first_buy_date'], date)
        elif type_ == 'Sell':
            if holdings[stock]['quantity'] < qty:
                continue
            sell_qty, cost_removed = qty, 0.0
            while sell_qty > 0 and lots[stock]:
                lot = lots[stock][0]
                lot_qty = lot['quantity']
                if sell_qty >= lot_qty:
                    cost_removed += lot_qty * lot['price']
                    sell_qty -= lot_qty
                    lots[stock].pop(0)
                else:
                    cost_removed += sell_qty * lot['price']
                    lot['quantity'] -= sell_qty
                    sell_qty = 0
            realized_gains[stock] += qty * price - cost_removed
            holdings[stock]['quantity'] -= qty
            holdings[stock]['total_cost'] -= cost_removed
            if holdings[stock]['quantity'] <= 0:
                del holdings[stock]

    # finalize avg_cost
    for stock in list(holdings.keys()):
        qty, total_cost = holdings[stock]['quantity'], holdings[stock]['total_cost']
        holdings[stock]['avg_cost'] = total_cost / qty if qty else 0.0
        holdings[stock]['realized_gain'] = realized_gains.get(stock, 0.0)

    return holdings
