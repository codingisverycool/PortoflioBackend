# index.py
import logging
import os
from flask import Flask, jsonify
from flask_cors import CORS

# Import DB setup
from api.database.db import ensure_tables

# Auth system
from api.auth.auth import login_manager
from api.auth.routes import auth_bp
from api.auth.auth import oauth 

# Finance sections
from api.finance.routes import finance_bp          # For portfolio, transactions, valuation, etc.
from api.finance.risk import risk_bp       # For risk questionnaire endpoints

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True)

    # Secret keys - ensure these are set in your Vercel environment
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

    # Init login manager
    login_manager.init_app(app)

    # Register blueprints
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
    except Exception as e:
        logger.exception("Error ensuring tables at startup: %s", e)

    return app

app = create_app()

if __name__ == '__main__':
    # Dev run
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
