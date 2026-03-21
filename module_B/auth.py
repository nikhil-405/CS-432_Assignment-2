import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, g, jsonify, redirect, request, url_for
from sqlalchemy import text
from sqlalchemy.orm import Session

from .config import Config
from .database import get_session
from .models import CoreMemberLink, CoreSession, CoreUser


@dataclass
class AuthContext:
    core_user: CoreUser
    core_session: CoreSession
    project_user_id: int | None
    project_organization_id: int | None


@dataclass
class AuthError:
    message: str
    status_code: int


def extract_session_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()

    token_from_query = request.args.get("session_token")
    if token_from_query:
        return token_from_query

    payload = request.get_json(silent=True) or {}
    token_from_json = payload.get("session_token")
    if token_from_json:
        return str(token_from_json)

    cookie_token = request.cookies.get("session_token")
    if cookie_token:
        return cookie_token

    return None


def issue_session(db_session: Session, user: CoreUser) -> tuple[str, datetime]:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=Config.SESSION_TTL_MINUTES)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "nonce": secrets.token_urlsafe(16),
        "exp": expires_at,
    }
    token = jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)

    db_session.add(
        CoreSession(
            core_user_id=user.id,
            session_token=token,
            expires_at=expires_at.replace(tzinfo=None),
            is_active=True,
        )
    )

    return token, expires_at


def _invalid_token_error() -> AuthError:
    return AuthError("Invalid session token", 401)


def validate_session(db_session: Session, token: str | None) -> tuple[AuthContext | None, AuthError | None]:
    if not token:
        return None, AuthError("No session found", 401)

    try:
        jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        session_row = (
            db_session.query(CoreSession)
            .filter(CoreSession.session_token == token)
            .one_or_none()
        )
        if session_row is not None:
            session_row.is_active = False
            db_session.commit()
        return None, AuthError("Session expired", 401)
    except jwt.InvalidTokenError:
        return None, _invalid_token_error()

    session_row = (
        db_session.query(CoreSession)
        .filter(CoreSession.session_token == token, CoreSession.is_active.is_(True))
        .one_or_none()
    )
    if session_row is None:
        return None, _invalid_token_error()

    if session_row.expires_at < datetime.utcnow():
        session_row.is_active = False
        db_session.commit()
        return None, AuthError("Session expired", 401)

    user = (
        db_session.query(CoreUser)
        .filter(CoreUser.id == session_row.core_user_id, CoreUser.is_active.is_(True))
        .one_or_none()
    )
    if user is None:
        return None, _invalid_token_error()

    member_link = (
        db_session.query(CoreMemberLink)
        .filter(CoreMemberLink.core_user_id == user.id)
        .one_or_none()
    )

    project_user_id = member_link.project_user_id if member_link is not None else None
    project_organization_id = None

    if project_user_id is not None:
        org_row = db_session.execute(
            text("SELECT `OrganizationID` FROM `Users` WHERE `UserID` = :user_id"),
            {"user_id": project_user_id},
        ).mappings().first()
        if org_row is not None:
            project_organization_id = int(org_row["OrganizationID"])

    return (
        AuthContext(
            core_user=user,
            core_session=session_row,
            project_user_id=project_user_id,
            project_organization_id=project_organization_id,
        ),
        None,
    )


def _auth_error_response(error: AuthError, page_mode: bool):
    if page_mode:
        return redirect(url_for("module_b.login_page"))
    return jsonify({"error": error.message}), error.status_code


def login_required(admin_only: bool = False, page_mode: bool = False):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_app.config.get("DB_READY", True):
                if page_mode:
                    return redirect(url_for("module_b.login_page"))
                return jsonify({"error": "Database is unavailable. Start MySQL and retry."}), 503

            db_session = get_session()
            token = extract_session_token()
            context, error = validate_session(db_session, token)
            if error is not None:
                db_session.close()
                return _auth_error_response(error, page_mode)

            if admin_only and context is not None and context.core_user.role != "Admin":
                db_session.close()
                if page_mode:
                    return redirect(url_for("module_b.dashboard"))
                return jsonify({"error": "Admin role required"}), 403

            g.db_session = db_session
            g.auth_context = context
            g.session_token = token
            return func(*args, **kwargs)

        return wrapper

    return decorator
