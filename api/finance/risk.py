# api/finance/risk.py
import json
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, make_response

from api.database.db import db_query, safe_str

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

risk_bp = Blueprint("finance_risk_bp", __name__)

# ----------------------
# RISK QUESTIONNAIRE
# ----------------------
RISK_QUESTIONNAIRE = {
    "questions": [
        {"id": "purposeOfInvesting", "options": {"a": {"score": 50}, "b": {"score": 40}, "c": {"score": 30}, "d": {"score": 20}, "e": {"score": 10}}},
        {"id": "lifeStage", "options": {"a": {"score": 50}, "b": {"score": 40}, "c": {"score": 30}, "d": {"score": 50}, "e": {"score": 20}, "f": {"score": 10}}},
        {"id": "expectedReturns", "options": {"a": {"score": 10}, "b": {"score": 20}, "c": {"score": 30}, "d": {"score": 40}, "e": {"score": 50}}},
        {"id": "derivativeProducts", "options": {"a": {"score": 50}, "b": {"score": 40}, "c": {"score": 30}, "d": {"score": 20}, "e": {"score": 10}}},
        {"id": "investmentHorizon", "options": {"a": {"score": 10}, "b": {"score": 20}, "c": {"score": 30}, "d": {"score": 40}, "e": {"score": 50}}},
        {"id": "marketDownturnReaction", "options": {"a": {"score": 50}, "b": {"score": 40}, "c": {"score": 30}, "d": {"score": 20}, "e": {"score": 10}}},
        {"id": "incomeStability", "options": {"a": {"score": 50}, "b": {"score": 40}, "c": {"score": 30}, "d": {"score": 20}, "e": {"score": 10}}},
        {"id": "emergencySavings", "options": {"a": {"score": 50}, "b": {"score": 40}, "c": {"score": 30}, "d": {"score": 20}, "e": {"score": 10}}},
        # Investment Experience
        {"id": "equityExperience", "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}},
        {"id": "fixedincomeExperience", "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}},
        {"id": "propertyExperience", "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}},
        {"id": "alternateinvestmentsExperience", "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}},
        {"id": "overseasinvestmentsExperience", "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}},
        {"id": "currenciesExperience", "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}},
        {"id": "commoditiesExperience", "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}},
        {"id": "passioninvestmentsExperience", "options": {"Extensive": {"score": 50}, "Moderate": {"score": 30}, "Limited": {"score": 10}, "None": {"score": 0}}}
    ],
    "risk_brackets": [
        {"min": 0, "max": 120, "name": "Defensive"},
        {"min": 130, "max": 250, "name": "Moderate"},
        {"min": 260, "max": 350, "name": "Aggressive"},
        {"min": 360, "max": 400, "name": "Very Aggressive"}
    ]
}

# ----------------------
# Helper: Score computation
# ----------------------
def _score_for_question(q_obj, raw_val):
    if raw_val is None:
        return 0
    val_str = safe_str(raw_val).strip()
    options = q_obj.get("options", {})
    for key, meta in options.items():
        if safe_str(key).strip().lower() == val_str.lower():
            return int(meta.get("score", 0))
    return 0

# ----------------------
# Routes
# ----------------------
@risk_bp.route("/api/risk/questionnaire", methods=["GET"])
def get_risk_questionnaire():
    return jsonify({"success": True, "questionnaire": RISK_QUESTIONNAIRE})

@risk_bp.route("/api/risk/submit", methods=["POST", "OPTIONS"])
def submit_risk():
    if request.method == "OPTIONS":
        resp = make_response()
        origin = request.headers.get("Origin", "*")
        resp.headers.update({
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Credentials": "true"
        })
        return resp

    try:
        data = request.get_json() or {}
        if not isinstance(data, dict):
            return jsonify({"success": False, "error": "Invalid payload"}), 400

        user_id = data.get("user_id")  # Required for UUID linkage
        if not user_id:
            return jsonify({"success": False, "error": "user_id missing"}), 400

        total_score = sum(_score_for_question(q, data.get(q.get("id"))) for q in RISK_QUESTIONNAIRE["questions"])

        risk_bracket = "Undetermined"
        for bracket in RISK_QUESTIONNAIRE["risk_brackets"]:
            if bracket["min"] <= total_score <= bracket["max"]:
                risk_bracket = bracket["name"]
                break

        profile_data = {
            "submitted_at": datetime.utcnow().isoformat(),
            "client_details": {
                "name": safe_str(data.get("applicantName")),
                "address": safe_str(data.get("applicantAddress")),
                "advisor_name": safe_str(data.get("advisorName")),
                "advisor_designation": safe_str(data.get("advisorDesignation")),
                "assessment_date": safe_str(data.get("assessmentDate")),
                "assessment_place": safe_str(data.get("assessmentPlace")),
            },
            "signature": safe_str(data.get("applicantSignature")),
            "total_score": total_score,
            "risk_bracket": risk_bracket,
            "interested_investments": data.get("interestedInvestments") if isinstance(data.get("interestedInvestments"), list) else [],
            "answers": data.get("answers") if isinstance(data.get("answers"), dict) else {},
        }

        db_query(
            """
            INSERT INTO user_risk_profiles (user_id, profile_json, total_score, risk_bracket, created_at)
            VALUES (%s, %s::jsonb, %s, %s, NOW())
            """,
            (user_id, json.dumps(profile_data), total_score, risk_bracket),
            commit=True,
        )

        return jsonify({"success": True, "total_score": total_score, "risk_bracket": risk_bracket})

    except Exception as e:
        logger.exception("Risk submission error: %s", e)
        return jsonify({"success": False, "error": "Failed to process risk assessment"}), 500

@risk_bp.route("/api/risk/check", methods=["GET"])
def check_risk_assessment():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "user_id missing"}), 400

    try:
        row = db_query(
            """
            SELECT profile_json
            FROM user_risk_profiles
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id,),
            fetchone=True,
        )
        if row:
            return jsonify({"success": True, "completed": True, "latest_assessment": row["profile_json"]})
        else:
            return jsonify({"success": True, "completed": False})
    except Exception as e:
        logger.exception("Check risk assessment error: %s", e)
        return jsonify({"success": False, "error": "Failed to fetch assessment"}), 500
