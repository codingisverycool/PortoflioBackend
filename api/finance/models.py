# api/finance/models.py
from api.database.db import db_query, get_conn, release_conn
from datetime import datetime

def fetch_transactions_for_user(user_id):
    rows = db_query(
        "SELECT type, stock, quantity, price, to_char(date,'YYYY-MM-DD') AS date, notes FROM transactions WHERE user_id = %s ORDER BY date ASC, created_at ASC;",
        (user_id,), fetchall=True
    )
    if not rows:
        return []
    txs = []
    for r in rows:
        txs.append({'type': r['type'], 'stock': r['stock'], 'quantity': int(r['quantity']), 'price': float(r['price']), 'date': r['date'], 'notes': r.get('notes') or ''})
    return txs

def insert_transaction_locked(user_id, tx_type, stock, quantity, price, date_str, notes):
    """
    Insert transaction while locking the user row (serialize per-user modifications).
    Returns None or raises.
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user_id,))
            cur.execute("SELECT COALESCE(SUM(CASE WHEN type='Buy' THEN quantity ELSE -quantity END),0) as qty FROM transactions WHERE user_id = %s AND UPPER(stock) = %s;", (user_id, stock))
            row = cur.fetchone()
            current_qty = int(row[0]) if row and row[0] is not None else 0
            if tx_type == 'Sell' and quantity > current_qty:
                conn.rollback()
                raise ValueError(f"Cannot sell {quantity} shares, only {current_qty} available")
            cur.execute("INSERT INTO transactions (user_id, type, stock, quantity, price, date, notes, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())", (user_id, tx_type, stock, quantity, price, date_str, notes))
            conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        release_conn(conn)
