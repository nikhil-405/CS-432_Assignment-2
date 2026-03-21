from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from werkzeug.security import generate_password_hash

from .config import Config
from .models import Base, CoreAuditState, CoreUser
from sqlalchemy import create_engine

_ENGINE: Engine | None = None
_SESSION_FACTORY = None

REQUIRED_PROJECT_TABLES = [
    "Users",
    "Organizations",
    "Roles",
    "Documents",
    "Permissions",
    "Logs",
    "Versions",
]


def get_engine() -> Engine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = create_engine(Config.database_url(), pool_pre_ping=True, future=True)
    return _ENGINE


def get_session() -> Session:
    global _SESSION_FACTORY
    if _SESSION_FACTORY is None:
        _SESSION_FACTORY = scoped_session(
            sessionmaker(bind=get_engine(), autoflush=False, autocommit=False, future=True)
        )
    return _SESSION_FACTORY()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_core_schema() -> None:
    engine = get_engine()
    Base.metadata.create_all(bind=engine)

    with session_scope() as session:
        tracking_key = "tracking_started_at"
        state = session.get(CoreAuditState, tracking_key)
        if state is None:
            state = CoreAuditState(
                state_key=tracking_key,
                state_value=datetime.now(timezone.utc).isoformat(),
            )
            session.add(state)


def seed_default_admin() -> None:
    with session_scope() as session:
        admin = (
            session.query(CoreUser)
            .filter(CoreUser.username == Config.DEFAULT_ADMIN_USERNAME)
            .one_or_none()
        )
        if admin is None:
            session.add(
                CoreUser(
                    username=Config.DEFAULT_ADMIN_USERNAME,
                    password_hash=generate_password_hash(Config.DEFAULT_ADMIN_PASSWORD),
                    role="Admin",
                    is_active=True,
                )
            )


def get_missing_project_tables() -> list[str]:
    try:
        inspector = inspect(get_engine())
        existing = {name.lower() for name in inspector.get_table_names()}
        return [name for name in REQUIRED_PROJECT_TABLES if name.lower() not in existing]
    except SQLAlchemyError:
        return REQUIRED_PROJECT_TABLES[:]


def next_numeric_id(session: Session, table_name: str, id_column: str) -> int:
    query = text(f"SELECT COALESCE(MAX(`{id_column}`), 0) + 1 AS next_id FROM `{table_name}`")
    result = session.execute(query).scalar_one()
    return int(result)


def run_sql_script(script_path: str) -> None:
    with open(script_path, "r", encoding="utf-8") as handle:
        script = handle.read()

    statements = [part.strip() for part in script.split(";") if part.strip()]
    with get_engine().begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
