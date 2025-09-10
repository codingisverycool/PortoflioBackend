from api.database.db import db_query, get_conn, release_conn, safe_str
from datetime import datetime
from typing import List, Dict, Optional
import json

# ----------------------
# Normalize transaction object
# ----------------------
def normalize_transaction(row: Dict) -> Dict:
    """
    Ensures a consistent schema for transaction objects
    across all endpoints.
    """
    return {
        "type": safe_str(row.get("type")).capitalize(),
        "stock": safe_str(row.get("stock")).upper(),
        "quantity": int(row.get("quantity", 0)),
        "price": float(row.get("price", 0.0)),
        "date": row.get("date"),
        "notes": safe_str(row.get("notes", "")),
        # Extra fields, may be enriched by utils later
        "name": safe_str(row.get("name", "")),
        "exchange": safe_str(row.get("exchange", "")),
        "currency": safe_str(row.get("currency", "")),
        "sector": safe_str(row.get("sector", "")),
        "value": float(row.get("value", row.get("quantity", 0) * row.get("price", 0.0))),
    }


# ----------------------
# Fetch transactions safely
# ----------------------
def fetch_transactions_for_user(user_id: str) -> List[Dict]:
    """
    Returns list of user's transactions (normalized).
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
        txs.append(normalize_transaction(r))
    return txs


# ----------------------
# Insert transaction with per-user locking
# ----------------------
def insert_transaction_locked(
    user_id: str,
    tx_type: str,
    stock: str,
    quantity: int,
    price: float,
    date_str: str,
    notes: str = ""
):
    """
    Insert transaction while locking the user row.
    Validates input, prevents overselling, commits safely.
    """
    if not user_id:
        raise ValueError("user_id required")

    tx_type = safe_str(tx_type).capitalize()
    if tx_type not in ("Buy", "Sell"):
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
            cur.execute(
                """
                SELECT COALESCE(SUM(CASE WHEN type='Buy' THEN quantity ELSE -quantity END),0) as qty
                FROM transactions 
                WHERE user_id = %s AND UPPER(stock) = %s;
                """,
                (user_id, stock),
            )
            row = cur.fetchone()
            current_qty = int(row[0]) if row and row[0] is not None else 0
            if tx_type == "Sell" and quantity > current_qty:
                raise ValueError(
                    f"Cannot sell {quantity} shares of {stock}, only {current_qty} available"
                )

            # Insert transaction
            cur.execute(
                """
                INSERT INTO transactions 
                (user_id, type, stock, quantity, price, date, notes, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                """,
                (user_id, tx_type, stock, quantity, price, date_obj.date(), notes),
            )
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


# ----------------------
# Risk profile helpers
# ----------------------
def fetch_latest_risk_profile(user_id: str) -> Optional[Dict]:
    """
    Returns the most recent risk profile for a user.
    """
    if not user_id:
        return None

    try:
        rows = db_query(
            """
            SELECT profile_json, to_char(submitted_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS submitted_at
            FROM risk_profiles
            WHERE user_id = %s
            ORDER BY submitted_at DESC
            LIMIT 1;
            """,
            (user_id,), fetchall=True
        )
    except Exception:
        return None

    if not rows:
        return None

    row = rows[0]
    try:
        profile = json.loads(row["profile_json"])
    except Exception:
        return None

    profile["submitted_at"] = row["submitted_at"]
    return profile


def insert_risk_profile(user_id: str, profile: Dict):
    """
    Insert a risk profile JSON payload for a user.
    """
    if not user_id:
        raise ValueError("user_id required")

    try:
        db_query(
            """
            INSERT INTO risk_profiles (user_id, profile_json, submitted_at)
            VALUES (%s, %s, NOW());
            """,
            (user_id, json.dumps(profile)),
            commit=True,
        )
    except Exception as e:
        raise RuntimeError(f"Failed to insert risk profile: {e}")
