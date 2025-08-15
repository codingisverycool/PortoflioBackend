# api/finance/utils.py
import logging
from datetime import datetime
import yfinance as yf

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

def get_stock_info(ticker):
    """
    Returns a normalized dict with price and metadata for a ticker.
    If Yahoo fails, returns minimal fallback dict.
    """
    try:
        stock = yf.Ticker(ticker)
        info = stock.info or {}
        hist = stock.history(period="1d")
        price = float(hist['Close'].iloc[-1]) if not hist.empty else 0.0
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
        return {'price': 0.0, 'shortName': ticker, 'name': ticker, 'currency': 'N/A', 'exchange': 'N/A', 'sector': 'N/A'}


def calculate_portfolio_irr(transactions):
    cash_flows = []
    dates = []
    for tx in transactions:
        amount = tx['quantity'] * tx['price']
        if tx['type'] == 'Buy':
            amount = -amount
        cash_flows.append(amount)
        try:
            dates.append(datetime.strptime(tx['date'], '%Y-%m-%d'))
        except Exception:
            pass
    if not cash_flows:
        return 0
    try:
        total_investment = sum(cf for cf in cash_flows if cf < 0)
        total_return = sum(cf for cf in cash_flows if cf > 0)
        if dates:
            days_held = max(1, (max(dates) - min(dates)).days)
        else:
            days_held = 1
        if total_investment == 0:
            return 0
        base = total_return / abs(total_investment)
        if base <= 0:
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
