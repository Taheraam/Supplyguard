"""Flask application factory for SupplyGuard web dashboard."""

import os
from pathlib import Path

from flask import Flask

from supplyguard.models import init_db
from supplyguard.web.routes import web_bp


def create_app(db_path: Path | str = "supplyguard.db") -> Flask:
    """Create and configure the Flask web dashboard instance.

    Args:
        db_path: Target SQLite database file.

    Returns:
        Configured Flask application.
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "supplyguard-local-key")
    app.config["DB_PATH"] = str(Path(db_path).resolve())

    # Initialize database engine and attach sessionmaker to app config
    _, session_factory = init_db(app.config["DB_PATH"])
    app.config["SESSION_FACTORY"] = session_factory

    app.register_blueprint(web_bp)
    return app
