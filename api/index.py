# api/index.py
import logging
import os
from flask import Flask, jsonify
from flask_cors import CORS

# Import DB setup
from api.database.db import ensure_tables

# Auth system
from api.auth.routes import auth_bp

# Finance sections
from api.finance.routes import finance_bp          # For portfolio, transactions, valuation, etc.
from api.finance.risk import risk_bp               # For risk questionnaire endpoints

logging.basicConfig(level=logging.INFO)  # DEBUG locally, INFO in prod
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True)

    # Secret key - ensure this is set in Vercel env
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
    if app.secret_key == "dev-secret":
        logger.warning("⚠️ Using fallback secret key! Set FLASK_SECRET_KEY in production.")

    # Register blueprints (no url_prefix to keep existing route names unchanged)
    app.register_blueprint(auth_bp)
    app.register_blueprint(finance_bp)
    app.register_blueprint(risk_bp)

    # Simple health check endpoint
    @app.route('/api/ping', methods=['GET'])
    def ping():
        return jsonify({'ping': 'pong'})

    # Ensure DB tables exist
    try:
        ensure_tables()
    except Exception:
        logger.exception("Error ensuring tables at startup")

    return app

app = create_app()

if __name__ == '__main__':
    # Dev run only
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
