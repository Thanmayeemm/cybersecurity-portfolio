"""
Flask application entrypoint: registers routes, initializes logging and DB.
"""
from __future__ import annotations

import app.env_bootstrap  # noqa: F401 — load .env with override=True before app.config

from flask import Flask, jsonify

from app import config
from app.models import incident as incident_model
from app.routes import bp as soar_bp
from app.utils.logger import setup_logging
from app.utils.slack_alerts import log_slack_env_status

logger = setup_logging(__name__)


def create_app() -> Flask:
    """Application factory for production WSGI servers (gunicorn, waitress, etc.)."""
    config.ensure_directories()
    incident_model.init_db()
    config.log_threat_intel_api_status(logger)
    log_slack_env_status()

    app = Flask(__name__)
    app.register_blueprint(soar_bp)

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "not found"}), 404

    @app.errorhandler(500)
    def server_err(_e):
        return jsonify({"error": "internal server error"}), 500

    logger.info("SOAR engine application created")
    return app


app = create_app()


if __name__ == "__main__":
    logger.info(
        "Starting dev server on %s:%s (debug=%s)",
        config.FLASK_HOST,
        config.FLASK_PORT,
        config.FLASK_DEBUG,
    )
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
