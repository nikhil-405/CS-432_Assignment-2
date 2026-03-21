from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, g
from sqlalchemy.exc import SQLAlchemyError

load_dotenv()

from .audit import ensure_audit_file
from .config import Config
from .database import get_missing_project_tables, init_core_schema, seed_default_admin
from .routes import bp


def create_app() -> Flask:
	app = Flask(__name__, template_folder="templates")
	app.config.from_object(Config)

	Path(app.config["AUDIT_LOG_PATH"]).parent.mkdir(parents=True, exist_ok=True)
	app.config["DB_READY"] = True

	with app.app_context():
		ensure_audit_file()
		try:
			init_core_schema()
			seed_default_admin()

			missing_tables = get_missing_project_tables()
			if missing_tables:
				app.logger.warning(
					"Project-specific tables are missing. Module B APIs that use Task-1 tables may fail. Missing: %s",
					", ".join(missing_tables),
				)
		except SQLAlchemyError as exc:
			app.config["DB_READY"] = False
			app.logger.warning(
				"Database initialization is unavailable. Start MySQL and retry. Details: %s",
				exc,
			)

	app.register_blueprint(bp)

	@app.teardown_request
	def close_request_session(exception=None):
		db_session = getattr(g, "db_session", None)
		if db_session is not None:
			if exception is not None:
				db_session.rollback()
			db_session.close()
			g.db_session = None

	return app
