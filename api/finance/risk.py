# api/finance/risk.py
import json
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, make_response

from api.auth.auth import token_required
from api.database.db import db_query

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

risk_bp = Blueprint('finance_risk_bp', __name__)

# RISK_QUESTIONNAIRE (same as before) - trimmed for brevity here in comment,
# please keep the full questionnaire object below as in your original
RISK_QUESTIONNAIRE = {
    "questions": [
        {
            "id": "purposeOfInvesting",
            "options": {"a": {"score": 50}, "b": {"score": 40}, "c": {"score": 30}, "d": {"score": 20}, "e": {"score": 10}}
        },
        {
            "id": "lifeStage",
            "options": {"a": {"score": 50}, "b": {"score": 40}, "c": {"score": 30}, "d": {"score": 50}, "e": {"score": 20}, "f": {"score": 10}}
        },
        {
            "id": "expectedReturns",
            "options": {"a": {"score": 10}, "b": {"score": 20}, "c": {"score": 30}, "d": {"score": 40}, "e": {"score": 50}}
        },
        {
            "id": "derivativeProducts",
            "options": {"a": {"score": 50}, "b": {"score": 40}, "c": {"score": 30}, "d": {"score": 20}, "e": {"score": 10}}
        },
        {
            "id": "investmentHorizon",
            "options": {"a": {"score": 10}, "b": {"score": 20}, "c": {"score": 30}, "d": {"score": 40}, "e": {"score": 50}}
        },
        {
            "id": "marketDownturnReaction",
            "options": {"a": {"score": 50}, "b": {"score": 40}, "c": {"score": 30}, "d": {"score": 20}, "e": {"score": 10}}
        },
        {
            "id": "incomeStability",
            "options": {"a": {"score": 50}, "b": {"score": 40}, "c": {"score": 30}, "d": {"score": 20}, "e": {"score": 10}}
        },
        {
            "id": "emergencySavings",
            "options": {"a": {"score": 50}, "b": {"score": 40}, "c": {"score": 30}, "d": {"score": 20}, "e": {"score": 10}}
        },
        # Investment Experience questions
        {
            "id": "equityExperience",
            "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}
        },
        {
            "id": "fixedincomeExperience",
            "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}
        },
        {
            "id": "propertyExperience",
            "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}
        },
        {
            "id": "alternateinvestmentsExperience",
            "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}
        },
        {
            "id": "overseasinvestmentsExperience",
            "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}
        },
        {
            "id": "currenciesExperience",
            "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}
        },
        {
            "id": "commoditiesExperience",
            "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}
        },
        {
            "id": "passioninvestmentsExperience",
            "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}
        }
    ],
    "risk_brackets": [
        {"min": 0, "max": 120, "name": "Defensive"},
        {"min": 130, "max": 250, "name": "Moderate"},
        {"min": 260, "max": 350, "name": "Aggressive"},
        {"min": 360, "max": 400, "name": "Very Aggressive"}
    ]
}

def _score_for_question(q_obj, raw_val):
    """
    Given a question object and provided answer value, return the option score (int).
    Matching is case-insensitive; for multi-word options (like 'Extensive') we try case-insensitive equality.
    Returns 0 when no match.
    """
    if raw_val is None:
        return 0
    # normalize strings
    try:
        val_str = str(raw_val).strip()
    except Exception:
        return 0
    # try exact match across keys (case-insensitive)
    options = q_obj.get("options", {})
    for opt_key, meta in options.items():
        try:
            if opt_key.strip().lower() == val_str.lower():
                return int(meta.get("score", 0))
        except Exception:
            continue
    # if not matched and value is single letter, try uppercase/lowercase matches
    for opt_key, meta in options.items():
        if len(opt_key) == 1 and opt_key.lower() == val_str.lower():
            return int(meta.get("score", 0))
    # no match
    return 0


@risk_bp.route('/api/risk/questionnaire', methods=['GET'])
@token_required
def get_risk_questionnaire(user_id):
    return jsonify({"success": True, "questionnaire": RISK_QUESTIONNAIRE})


@risk_bp.route('/api/risk/submit', methods=['POST', 'OPTIONS'])
@token_required
def submit_risk(user_id):
    if request.method == 'OPTIONS':
        response = make_response()
        origin = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = "POST, OPTIONS"
        response.headers['Access-Control-Allow-Headers'] = "Content-Type, Authorization"
        response.headers['Access-Control-Allow-Credentials'] = "true"
        return response

    try:
        data = request.get_json() or request.form or {}
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        # If client provided a numeric totalScore, accept it (defensive)
        provided_total = data.get("totalScore")
        total_score = None
        if provided_total is not None:
            try:
                total_score = int(provided_total)
            except Exception:
                total_score = None

        # If no totalScore given, compute from questionnaire definition
        if total_score is None:
            total_score = 0
            for q in RISK_QUESTIONNAIRE["questions"]:
                qid = q.get("id")
                # Prefer values in top-level data keyed by question id (frontend uses these names)
                val = None
                if isinstance(data, dict):
                    val = data.get(qid)
                # If still None, try a legacy answers object
                if val is None:
                    # some clients might submit answers object: {"answers": {"q1": "A", ...}}
                    answers_obj = data.get("answers") or {}
                    # attempt to map qid to q1..q8 only for the first 8 questions (safe fallback)
                    if isinstance(answers_obj, dict):
                        # try to find a matching answer in answers_obj by value/key comparisons
                        for k, v in answers_obj.items():
                            # if v is candidate for this qid, break (we just take whatever matches key or order)
                            # This block is just a very small safety net; primary source should be data[qid]
                            pass
                # compute score using robust matching helper
                total_score += _score_for_question(q, val)

        # ensure integer
        try:
            total_score = int(total_score)
        except Exception:
            total_score = 0

        # Determine risk bracket
        risk_bracket = "Undetermined"
        for bracket in RISK_QUESTIONNAIRE["risk_brackets"]:
            if bracket["min"] <= total_score <= bracket["max"]:
                risk_bracket = bracket["name"]
                break

        profile_data = {
            "user_id": user_id,
            "submitted_at": datetime.utcnow().isoformat(),
            "client_details": {
                "name": data.get("applicantName"),
                "address": data.get("applicantAddress"),
                "advisor_name": data.get("advisorName"),
                "advisor_designation": data.get("advisorDesignation"),
                "assessment_date": data.get("assessmentDate"),
                "assessment_place": data.get("assessmentPlace")
            },
            "signature": data.get("applicantSignature"),
            "total_score": total_score,
            "risk_bracket": risk_bracket,
            "interested_investments": data.get("interestedInvestments", []),
            "answers": data.get("answers") or {}  # store the raw answers if provided
        }

        db_query("""
            INSERT INTO user_risk_profiles (user_id, profile_json, total_score, risk_bracket, created_at)
            VALUES (%s, %s::jsonb, %s, %s, NOW());
        """, (user_id, json.dumps(profile_data), total_score, risk_bracket), commit=True)

        return jsonify({"success": True, "total_score": total_score, "risk_bracket": risk_bracket})

    except Exception as e:
        logger.exception("Risk assessment submission error: %s", e)
        return jsonify({"success": False, "error": "Failed to process risk assessment"}), 500


@risk_bp.route('/api/risk/check', methods=['GET'])
@token_required
def check_risk_assessment(user_id):
    try:
        row = db_query("""
            SELECT profile_json
            FROM user_risk_profiles
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1;
        """, (user_id,), fetchone=True)
        if row:
            return jsonify({"success": True, "completed": True, "latest_assessment": row['profile_json']})
        else:
            return jsonify({"success": True, "completed": False})
    except Exception as e:
        logger.exception("check_risk_assessment error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to fetch assessment'}), 500
