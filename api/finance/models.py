# api/finance/models.py
from api.database.db import db_query, get_conn, release_conn, safe_str
from datetime import datetime
from typing import List, Dict

# ----------------------
# Fetch transactions safely
# ----------------------
def fetch_transactions_for_user(user_id: str) -> List[Dict]:
    """
    Returns list of user's transactions.
    """
    if not user_id:
        return []

    try:
        rows = db_query(
            """
            SELECT type, stock, quantity, price, 
                   to_char(date,'YYYY-MM-DD') AS date, notes 
            FROM transactions 
            WHERE user_id = %s 
            ORDER BY date ASC, created_at ASC;
            """,
            (user_id,), fetchall=True
        )
    except Exception:
        return []

    txs = []
    for r in rows or []:
        txs.append({
            'type': r['type'],
            'stock': safe_str(r['stock']).upper(),
            'quantity': int(r['quantity']),
            'price': float(r['price']),
            'date': r['date'],
            'notes': safe_str(r.get('notes', ''))
        })
    return txs


# ----------------------
# Insert transaction with per-user locking
# ----------------------
def insert_transaction_locked(user_id: str, tx_type: str, stock: str, quantity: int, price: float, date_str: str, notes: str = ''):
    """
    Insert transaction while locking the user row.
    Validates input, prevents overselling, commits safely.
    """
    if not user_id:
        raise ValueError("user_id required")
    tx_type = safe_str(tx_type).capitalize()
    if tx_type not in ('Buy', 'Sell'):
        raise ValueError("tx_type must be 'Buy' or 'Sell'")

    stock = safe_str(stock).upper()
    if not stock:
        raise ValueError("stock symbol required")

    try:
        quantity = int(quantity)
        price = float(price)
        if quantity <= 0 or price < 0:
            raise ValueError("quantity must be >0 and price >=0")
    except Exception:
        raise ValueError("Invalid quantity or price")

    notes = safe_str(notes)

    # Validate date
    try:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d")
    except Exception:
        raise ValueError("date must be YYYY-MM-DD format")

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # Lock user row to serialize transactions
            cur.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user_id,))

            # Check available quantity for sell
            cur.execute("""
                SELECT COALESCE(SUM(CASE WHEN type='Buy' THEN quantity ELSE -quantity END),0) as qty
                FROM transactions 
                WHERE user_id = %s AND UPPER(stock) = %s;
            """, (user_id, stock))
            row = cur.fetchone()
            current_qty = int(row[0]) if row and row[0] is not None else 0
            if tx_type == 'Sell' and quantity > current_qty:
                raise ValueError(f"Cannot sell {quantity} shares of {stock}, only {current_qty} available")

            # Insert transaction
            cur.execute("""
                INSERT INTO transactions (user_id, type, stock, quantity, price, date, notes, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """, (user_id, tx_type, stock, quantity, price, date_obj.date(), notes))
            conn.commit()
    except Exception:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        raise
    finally:
        release_conn(conn)
