import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import current_app
from sqlalchemy.orm import Session

from .models import CoreAuditLog


def ensure_audit_file() -> None:
    audit_path = Path(current_app.config["AUDIT_LOG_PATH"])
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    if not audit_path.exists():
        audit_path.write_text("", encoding="utf-8")


def log_audit_event(
    db_session: Session,
    action: str,
    entity: str,
    entity_id: str | None,
    status: str,
    actor_core_user_id: int | None,
    session_token: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    details_json = json.dumps(details or {}, default=str)
    log_row = CoreAuditLog(
        actor_core_user_id=actor_core_user_id,
        session_token=session_token,
        action=action,
        entity=entity,
        entity_id=entity_id,
        status=status,
        details_json=details_json,
    )
    db_session.add(log_row)
    db_session.flush()

    line = {
        "id": log_row.id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor_core_user_id": actor_core_user_id,
        "session_token": session_token,
        "action": action,
        "entity": entity,
        "entity_id": entity_id,
        "status": status,
        "details": details or {},
    }

    audit_path = Path(current_app.config["AUDIT_LOG_PATH"])
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, default=str) + "\n")
