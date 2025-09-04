# api/finance/transactions/csv_upload.py
from datetime import datetime
import csv
from io import StringIO
from decimal import Decimal, InvalidOperation

# Expected header names (lowercase)
EXPECTED_HEADERS = ["date", "stock", "type", "quantity", "price", "notes", "source"]

def _is_iso_date(s):
    if not isinstance(s, str):
        return False
    try:
        # strict YYYY-MM-DD
        datetime.strptime(s, "%Y-%m-%d")
        return True
    except Exception:
        return False

def _to_int(s):
    try:
        if isinstance(s, int):
            return s
        s2 = str(s).strip()
        if s2 == "":
            return None
        return int(s2)
    except Exception:
        return None

def _to_decimal(s):
    try:
        if isinstance(s, Decimal):
            return s
        s2 = str(s).strip()
        if s2 == "":
            return None
        # allow commas like "1,234.56"
        s2 = s2.replace(",", "")
        return Decimal(s2)
    except (InvalidOperation, Exception):
        return None

def validate_and_normalize_transaction(raw):
    """
    raw: dict with keys (case-insensitive), e.g. {'date': '2025-01-01', 'stock': 'AAPL', ...}
    Returns: (normalized_row, errors)
      - normalized_row: dict with exact keys: date (YYYY-MM-DD str), stock (upper), type ('Buy'/'Sell'),
                        quantity (int), price (Decimal), notes (str or None), source (str or None)
      - errors: list[str] (empty if valid)
    """
    errors = []
    # defensive copy
    r = { (k or "").strip().lower(): (v if v is not None else "") for k, v in (raw.items() if isinstance(raw, dict) else []) }

    # required keys check (we allow missing optional notes/source)
    for req in ["date", "stock", "type", "quantity", "price"]:
        if req not in r:
            errors.append(f"Missing field: {req}")

    # date
    date_str = str(r.get("date", "")).strip()
    if not _is_iso_date(date_str):
        errors.append("Invalid date format; expected YYYY-MM-DD")
    else:
        # disallow future dates
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d").date()
            if dt > datetime.utcnow().date():
                errors.append("Transaction date cannot be in the future")
        except Exception:
            # already covered, but keep safe
            errors.append("Invalid date value")

    # stock
    stock = str(r.get("stock", "")).strip()
    if not stock:
        errors.append("Stock/ticker is required")

    # type -> must be Buy or Sell (case sensitive in DB)
    typ = str(r.get("type", "")).strip()
    if not typ:
        errors.append("Type is required (Buy/Sell)")
    else:
        t_norm = typ.lower()
        if t_norm == "buy":
            typ_final = "Buy"
        elif t_norm == "sell":
            typ_final = "Sell"
        else:
            errors.append("Type must be 'Buy' or 'Sell' (case-insensitive input allowed)")

    # quantity -> integer > 0
    qty = _to_int(r.get("quantity", ""))
    if qty is None:
        errors.append("Quantity must be an integer")
    else:
        if qty <= 0:
            errors.append("Quantity must be > 0")

    # price -> numeric >= 0
    price_dec = _to_decimal(r.get("price", ""))
    if price_dec is None:
        errors.append("Price must be a number")
    else:
        if price_dec < 0:
            errors.append("Price must be >= 0")

    # notes/source optional
    notes = r.get("notes", "")
    source = r.get("source", "")

    normalized = {
        "date": date_str,
        "stock": stock.upper() if isinstance(stock, str) else stock,
        "type": typ_final if 'typ_final' in locals() else typ,
        "quantity": qty if isinstance(qty, int) else qty,
        "price": price_dec if isinstance(price_dec, Decimal) else price_dec,
        "notes": notes if notes != "" else None,
        "source": source if source != "" else None,
    }

    return normalized, errors

def parse_csv_string(content):
    """
    Parse CSV text content, expected headers (case-insensitive).
    Returns list of dict rows with header names lowercased.
    """
    si = StringIO(content)
    reader = csv.DictReader(si)
    # normalize headers to lowercase
    rows = []
    for r in reader:
        normalized = {}
        for k, v in r.items():
            if k is None:
                continue
            normalized[k.strip().lower()] = v
        rows.append(normalized)
    return rows
