from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, current_app, g, jsonify, make_response, redirect, render_template, request, url_for
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from .audit import log_audit_event
from .auth import issue_session, login_required, validate_session
from .database import get_missing_project_tables, get_session, next_numeric_id
from .models import CoreAuditState, CoreGroupMembership, CoreMemberLink, CoreSession, CoreUser

bp = Blueprint("module_b", __name__)


def _payload() -> dict[str, Any]:
    if request.is_json:
        return request.get_json(silent=True) or {}
    return request.form.to_dict(flat=True)


def _to_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off", ""}:
            return False
    return bool(value)


def _extract_document_password(data: dict[str, Any]) -> str | None:
    for key in ("DocumentPassword", "document_password", "doc_password", "password"):
        value = data.get(key)
        if value is not None:
            return str(value)
    return None


def _archived_username(username: str, core_user_id: int) -> str:
    # Keep a traceable tombstone while freeing the original username for reuse.
    suffix = f"__deleted__{core_user_id}__{int(datetime.utcnow().timestamp())}"
    max_len = 80
    base_len = max_len - len(suffix)
    if base_len <= 0:
        return suffix[-max_len:]
    return f"{username[:base_len]}{suffix}"


def _project_tables_ready():
    if not current_app.config.get("DB_READY", True):
        return (
            False,
            jsonify({"error": "Database is unavailable. Start MySQL and retry."}),
            503,
        )

    missing = get_missing_project_tables()
    if missing:
        return False, jsonify({
            "error": "Required project tables are missing",
            "missing_tables": missing,
        }), 500
    return True, None, None


def _format_username_as_display_name(username: str) -> str:
    cleaned = username.replace("_", " ").replace(".", " ").replace("-", " ").strip()
    if not cleaned:
        return "User"
    return " ".join(part.capitalize() for part in cleaned.split())


def _resolve_display_name(db_session, auth_context) -> str:
    raw_username = str(auth_context.core_user.username or "").strip()
    formatted_username = _format_username_as_display_name(raw_username)

    if auth_context.project_user_id is not None:
        row = db_session.execute(
            text("SELECT `Name` FROM `Users` WHERE `UserID` = :user_id"),
            {"user_id": auth_context.project_user_id},
        ).mappings().first()
        if row is not None:
            name = str(row.get("Name") or "").strip()
            if name:
                if raw_username and name == raw_username:
                    return formatted_username
                if any(ch in name for ch in ("_", "-", ".")):
                    return _format_username_as_display_name(name)
                return name

    return formatted_username


def _document_from_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "DocID": row["DocID"],
        "DocName": row["DocName"],
        "DocSize": row["DocSize"],
        "NumberOfPages": row["NumberOfPages"],
        "FilePath": row["FilePath"],
        "ConfidentialityLevel": row["ConfidentialityLevel"],
        "IsPasswordProtected": bool(row["IsPasswordProtected"]),
        "OwnerName": row.get("OwnerName"),
        "OwnerUserID": row["OwnerUserID"],
        "OrganizationName": row.get("OrganizationName"),
        "OrganizationID": row["OrganizationID"],
        "CreatedAt": _to_iso(row["CreatedAt"]),
        "LastModifiedAt": _to_iso(row["LastModifiedAt"]),
    }


def _document_exists(db_session, doc_id: int) -> bool:
    return db_session.execute(
        text("SELECT 1 FROM `Documents` WHERE `DocID` = :doc_id"),
        {"doc_id": doc_id},
    ).first() is not None


def _count_accessible_documents(db_session, auth_context) -> int:
    if auth_context.core_user.role == "Admin":
        return int(db_session.execute(text("SELECT COUNT(*) FROM `Documents`")).scalar_one())

    if auth_context.project_user_id is None:
        return 0

    return int(
        db_session.execute(
            text(
                """
                SELECT COUNT(*)
                FROM `Documents` d
                WHERE d.`OwnerUserID` = :project_user_id
                   OR EXISTS (
                        SELECT 1
                        FROM `Permissions` p
                        WHERE p.`DocID` = d.`DocID`
                          AND p.`UserID` = :project_user_id
                          AND p.`AccessType` IN ('View', 'Edit', 'Delete')
                   )
                """
            ),
            {"project_user_id": auth_context.project_user_id},
        ).scalar_one()
    )


def _list_accessible_documents(db_session, auth_context, limit: int) -> list[dict[str, Any]]:
    if auth_context.core_user.role == "Admin":
        rows = db_session.execute(
            text(
                """
                SELECT
                    d.*,
                    u.`Name` AS `OwnerName`,
                    o.`OrgName` AS `OrganizationName`
                FROM `Documents` d
                LEFT JOIN `Users` u ON u.`UserID` = d.`OwnerUserID`
                LEFT JOIN `Organizations` o ON o.`OrganizationID` = d.`OrganizationID`
                ORDER BY d.`LastModifiedAt` DESC
                LIMIT :limit
                """
            ),
            {"limit": limit},
        ).mappings().all()

        docs = []
        for row in rows:
            doc = _document_from_row(dict(row))
            doc["CanView"] = True
            doc["CanEdit"] = True
            doc["CanDelete"] = True
            doc["IsOwner"] = True
            docs.append(doc)
        return docs

    if auth_context.project_user_id is None:
        return []

    rows = db_session.execute(
        text(
            """
            SELECT
                d.*,
                u.`Name` AS `OwnerName`,
                o.`OrgName` AS `OrganizationName`,
                CASE WHEN d.`OwnerUserID` = :project_user_id THEN 1 ELSE 0 END AS `IsOwner`,
                EXISTS (
                    SELECT 1 FROM `Permissions` p
                    WHERE p.`DocID` = d.`DocID`
                      AND p.`UserID` = :project_user_id
                      AND p.`AccessType` IN ('View', 'Edit', 'Delete')
                ) AS `HasViewPermission`,
                EXISTS (
                    SELECT 1 FROM `Permissions` p
                    WHERE p.`DocID` = d.`DocID`
                      AND p.`UserID` = :project_user_id
                      AND p.`AccessType` IN ('Edit', 'Delete')
                ) AS `HasEditPermission`,
                EXISTS (
                    SELECT 1 FROM `Permissions` p
                    WHERE p.`DocID` = d.`DocID`
                      AND p.`UserID` = :project_user_id
                      AND p.`AccessType` = 'Delete'
                ) AS `HasDeletePermission`
            FROM `Documents` d
            LEFT JOIN `Users` u ON u.`UserID` = d.`OwnerUserID`
            LEFT JOIN `Organizations` o ON o.`OrganizationID` = d.`OrganizationID`
            WHERE d.`OwnerUserID` = :project_user_id
               OR EXISTS (
                    SELECT 1 FROM `Permissions` p
                    WHERE p.`DocID` = d.`DocID`
                      AND p.`UserID` = :project_user_id
                      AND p.`AccessType` IN ('View', 'Edit', 'Delete')
               )
            ORDER BY d.`LastModifiedAt` DESC
            LIMIT :limit
            """
        ),
        {"project_user_id": auth_context.project_user_id, "limit": limit},
    ).mappings().all()

    docs = []
    for row in rows:
        row_dict = dict(row)
        is_owner = bool(row_dict.get("IsOwner"))
        can_view = is_owner or bool(row_dict.get("HasViewPermission"))
        can_edit = is_owner or bool(row_dict.get("HasEditPermission"))
        can_delete = is_owner or bool(row_dict.get("HasDeletePermission"))

        doc = _document_from_row(row_dict)
        doc["CanView"] = can_view
        doc["CanEdit"] = can_edit
        doc["CanDelete"] = can_delete
        doc["IsOwner"] = is_owner
        docs.append(doc)

    return docs


def _get_document_with_access(db_session, auth_context, doc_id: int) -> dict[str, Any] | None:
    if auth_context.core_user.role == "Admin":
        row = db_session.execute(
            text(
                """
                SELECT
                    d.*,
                    u.`Name` AS `OwnerName`,
                    o.`OrgName` AS `OrganizationName`
                FROM `Documents` d
                LEFT JOIN `Users` u ON u.`UserID` = d.`OwnerUserID`
                LEFT JOIN `Organizations` o ON o.`OrganizationID` = d.`OrganizationID`
                WHERE d.`DocID` = :doc_id
                """
            ),
            {"doc_id": doc_id},
        ).mappings().first()
        if row is None:
            return None

        doc = _document_from_row(dict(row))
        doc["CanView"] = True
        doc["CanEdit"] = True
        doc["CanDelete"] = True
        doc["IsOwner"] = True
        return doc

    if auth_context.project_user_id is None:
        return None

    row = db_session.execute(
        text(
            """
            SELECT
                d.*,
                u.`Name` AS `OwnerName`,
                o.`OrgName` AS `OrganizationName`,
                CASE WHEN d.`OwnerUserID` = :project_user_id THEN 1 ELSE 0 END AS `IsOwner`,
                EXISTS (
                    SELECT 1 FROM `Permissions` p
                    WHERE p.`DocID` = d.`DocID`
                      AND p.`UserID` = :project_user_id
                      AND p.`AccessType` IN ('View', 'Edit', 'Delete')
                ) AS `HasViewPermission`,
                EXISTS (
                    SELECT 1 FROM `Permissions` p
                    WHERE p.`DocID` = d.`DocID`
                      AND p.`UserID` = :project_user_id
                      AND p.`AccessType` IN ('Edit', 'Delete')
                ) AS `HasEditPermission`,
                EXISTS (
                    SELECT 1 FROM `Permissions` p
                    WHERE p.`DocID` = d.`DocID`
                      AND p.`UserID` = :project_user_id
                      AND p.`AccessType` = 'Delete'
                ) AS `HasDeletePermission`
            FROM `Documents` d
                LEFT JOIN `Users` u ON u.`UserID` = d.`OwnerUserID`
                LEFT JOIN `Organizations` o ON o.`OrganizationID` = d.`OrganizationID`
            WHERE d.`DocID` = :doc_id
              AND (
                    d.`OwnerUserID` = :project_user_id
                 OR EXISTS (
                        SELECT 1 FROM `Permissions` p
                        WHERE p.`DocID` = d.`DocID`
                          AND p.`UserID` = :project_user_id
                          AND p.`AccessType` IN ('View', 'Edit', 'Delete')
                 )
              )
            """
        ),
        {"doc_id": doc_id, "project_user_id": auth_context.project_user_id},
    ).mappings().first()

    if row is None:
        return None

    row_dict = dict(row)
    is_owner = bool(row_dict.get("IsOwner"))
    can_view = is_owner or bool(row_dict.get("HasViewPermission"))
    can_edit = is_owner or bool(row_dict.get("HasEditPermission"))
    can_delete = is_owner or bool(row_dict.get("HasDeletePermission"))

    doc = _document_from_row(row_dict)
    doc["CanView"] = can_view
    doc["CanEdit"] = can_edit
    doc["CanDelete"] = can_delete
    doc["IsOwner"] = is_owner
    return doc


def _verify_document_password(db_session, doc_id: int, candidate_password: str) -> bool:
    password_row = db_session.execute(
        text("SELECT `PasswordHash` FROM `DocPasswords` WHERE `DocID` = :doc_id"),
        {"doc_id": doc_id},
    ).mappings().first()
    if password_row is None:
        return False
    return check_password_hash(str(password_row["PasswordHash"]), candidate_password)


@bp.route("/", methods=["GET"])
def home():
    return redirect(url_for("module_b.login_page"))
    # return jsonify({"message": })


@bp.route("/api/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "module_b",
            "db_ready": bool(current_app.config.get("DB_READY", False)),
        }
    )


@bp.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@bp.route("/login", methods=["POST"])
def login_api():
    if not current_app.config.get("DB_READY", True):
        return jsonify({"error": "Database is unavailable. Start MySQL and retry."}), 503

    data = _payload()
    username = str(data.get("user") or data.get("username") or "").strip()
    password = str(data.get("password") or "")

    if not username or not password:
        return jsonify({"error": "Missing parameters"}), 401

    db_session = get_session()
    try:
        user = (
            db_session.query(CoreUser)
            .filter(CoreUser.username == username, CoreUser.is_active.is_(True))
            .one_or_none()
        )
        if user is None:
            return jsonify({"error": "Invalid credentials"}), 401

        member_link = (
            db_session.query(CoreMemberLink)
            .filter(CoreMemberLink.core_user_id == user.id)
            .one_or_none()
        )

        password_valid = False
        if member_link is not None:
            password_row = db_session.execute(
                text(
                    """
                    SELECT `PasswordHash`
                    FROM `UserPasswords`
                    WHERE `UserID` = :user_id
                      AND `LoginUsername` = :login_username
                      AND `IsActive` = 1
                    """
                ),
                {"user_id": member_link.project_user_id, "login_username": username},
            ).mappings().first()

            if password_row is not None:
                password_valid = check_password_hash(str(password_row["PasswordHash"]), password)
            else:
                # Backward compatibility for members created before UserPasswords existed.
                password_valid = check_password_hash(user.password_hash, password)
        else:
            # Core users without project mapping (for example default admin).
            password_valid = check_password_hash(user.password_hash, password)

        if not password_valid:
            return jsonify({"error": "Invalid credentials"}), 401

        token, expires_at = issue_session(db_session, user)
        db_session.commit()

        payload = {
            "message": "Login successful",
            "session_token": token,
            "expiry": expires_at.isoformat(),
        }

        if request.is_json:
            # For JSON requests, return token but also set cookie so page-mode routes work
            response = make_response(jsonify(payload), 200)
            response.set_cookie(
                "session_token",
                token,
                httponly=True,
                samesite="Lax",
                secure=False,
            )
            return response

        response = make_response(redirect(url_for("module_b.dashboard")))
        response.set_cookie(
            "session_token",
            token,
            httponly=True,
            samesite="Lax",
            secure=False,
        )
        return response
    finally:
        db_session.close()


@bp.route("/isAuth", methods=["GET"])
def is_auth():
    if not current_app.config.get("DB_READY", True):
        return jsonify({"error": "Database is unavailable. Start MySQL and retry."}), 503

    token = None

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()

    if token is None:
        token = request.args.get("session_token")

    if token is None:
        payload = request.get_json(silent=True) or {}
        token = payload.get("session_token")

    if token is None:
        token = request.cookies.get("session_token")

    db_session = get_session()
    try:
        context, error = validate_session(db_session, token)
        if error is not None:
            return jsonify({"error": error.message}), error.status_code

        return (
            jsonify(
                {
                    "message": "User is authenticated",
                    "username": context.core_user.username,
                    "role": context.core_user.role,
                    "expiry": _to_iso(context.core_session.expires_at),
                }
            ),
            200,
        )
    finally:
        db_session.close()


@bp.route("/logout", methods=["POST"])
@login_required()
def logout():
    db_session = g.db_session
    auth_context = g.auth_context

    auth_context.core_session.is_active = False
    db_session.commit()

    response = jsonify({"message": "Logged out"})
    response.delete_cookie("session_token")
    return response


@bp.route("/dashboard", methods=["GET"])
@login_required(page_mode=True)
def dashboard():
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    auth_context = g.auth_context
    page = request.args.get("page", 1, type=int)
    search = request.args.get("search", "", type=str).strip()
    per_page = 10
    offset = (page - 1) * per_page
    role_options = []
    organization_options = []

    if auth_context.core_user.role == "Admin":
        # Build search query
        base_query = "SELECT `UserID`, `Name`, `Email`, `OrganizationID`, `AccountStatus` FROM `Users`"
        count_query = "SELECT COUNT(*) FROM `Users`"
        params = {}

        if search:
            search_filter = " WHERE (`Name` LIKE :search OR `Email` LIKE :search OR CAST(`UserID` AS CHAR) LIKE :search)"
            base_query += search_filter
            count_query += search_filter
            params["search"] = f"%{search}%"

        # Get total count
        total_count = int(db_session.execute(text(count_query), params).scalar_one())

        # Get paginated results
        base_query += " ORDER BY `UserID` LIMIT :limit OFFSET :offset"
        params["limit"] = per_page
        params["offset"] = offset
        member_rows = db_session.execute(text(base_query), params).mappings().all()
        total_pages = (total_count + per_page - 1) // per_page

        role_options = db_session.execute(
            text(
                """
                SELECT `RoleID`, `RoleName`
                FROM `Roles`
                ORDER BY `RoleID`
                """
            )
        ).mappings().all()

        organization_options = db_session.execute(
            text(
                """
                SELECT `OrganizationID`, `OrgName`
                FROM `Organizations`
                ORDER BY `OrganizationID`
                """
            )
        ).mappings().all()
    else:
        member_rows = []
        total_pages = 1

    document_count = _count_accessible_documents(db_session, auth_context)
    display_name = _resolve_display_name(db_session, auth_context)

    return render_template(
        "dashboard.html",
        user=display_name,
        display_name=display_name,
        username=auth_context.core_user.username,
        role=auth_context.core_user.role,
        members=member_rows,
        role_options=role_options,
        organization_options=organization_options,
        document_count=document_count,
        page=page,
        total_pages=total_pages,
        search=search,
    )


@bp.route("/portfolio/<int:member_id>", methods=["GET"])
@login_required(page_mode=True)
def portfolio(member_id: int):
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    auth_context = g.auth_context

    member_row = db_session.execute(
        text(
            """
            SELECT u.`UserID`, u.`Name`, u.`Email`, u.`Age`, u.`RoleID`,
                   r.`RoleName`, u.`OrganizationID`, o.`OrgName`, u.`AccountStatus`
            FROM `Users` u
            LEFT JOIN `Roles` r ON r.`RoleID` = u.`RoleID`
            LEFT JOIN `Organizations` o ON o.`OrganizationID` = u.`OrganizationID`
            WHERE u.`UserID` = :member_id
            """
        ),
        {"member_id": member_id},
    ).mappings().first()

    if member_row is None:
        return jsonify({"error": "Member not found"}), 404

    if auth_context.core_user.role != "Admin":
        if auth_context.project_organization_id is None:
            return jsonify({"error": "Insufficient portfolio access"}), 403
        if int(member_row["OrganizationID"]) != int(auth_context.project_organization_id):
            return jsonify({"error": "Insufficient portfolio access"}), 403

    # Find the CoreUser linked to this project user (if admin needs to deactivate)
    core_user_id = None
    if auth_context.core_user.role == "Admin":
        member_link = db_session.query(CoreMemberLink).filter(
            CoreMemberLink.project_user_id == member_id
        ).one_or_none()
        if member_link:
            core_user_id = member_link.core_user_id

    return render_template(
        "portfolio.html",
        member=member_row,
        is_admin=auth_context.core_user.role == "Admin",
        core_user_id=core_user_id,
    )


@bp.route("/members", methods=["GET"])
@login_required(page_mode=True)
def members_page():
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    auth_context = g.auth_context

    if auth_context.core_user.role == "Admin":
        member_rows = db_session.execute(
            text(
                """
                SELECT u.`UserID`, u.`Name`, u.`Email`, u.`OrganizationID`,
                       o.`OrgName` AS `OrganizationName`, u.`AccountStatus`
                FROM `Users` u
                LEFT JOIN `Organizations` o ON o.`OrganizationID` = u.`OrganizationID`
                ORDER BY u.`UserID`
                LIMIT 300
                """
            )
        ).mappings().all()
    else:
        if auth_context.project_organization_id is None:
            return jsonify({"error": "Current user is not mapped to project member data"}), 403

        member_rows = db_session.execute(
            text(
                """
                SELECT u.`UserID`, u.`Name`, u.`Email`, u.`OrganizationID`,
                       o.`OrgName` AS `OrganizationName`, u.`AccountStatus`
                FROM `Users` u
                LEFT JOIN `Organizations` o ON o.`OrganizationID` = u.`OrganizationID`
                WHERE u.`OrganizationID` = :org_id
                ORDER BY u.`UserID`
                LIMIT 300
                """
            ),
            {"org_id": auth_context.project_organization_id},
        ).mappings().all()

    display_name = _resolve_display_name(db_session, auth_context)

    return render_template(
        "members.html",
        username=auth_context.core_user.username,
        display_name=display_name,
        role=auth_context.core_user.role,
        members=member_rows,
    )


@bp.route("/documents", methods=["GET"])
@login_required(page_mode=True)
def documents_page():
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    auth_context = g.auth_context
    limit = min(max(int(request.args.get("limit", 100)), 1), 300)
    docs = _list_accessible_documents(db_session, auth_context, limit)
    display_name = _resolve_display_name(db_session, auth_context)

    return render_template(
        "documents.html",
        username=auth_context.core_user.username,
        display_name=display_name,
        role=auth_context.core_user.role,
        user_id=auth_context.project_user_id,
        organization_id=auth_context.project_organization_id,
        documents=docs,
    )


@bp.route("/documents/<int:doc_id>/view", methods=["GET", "POST"])
@login_required(page_mode=True)
def document_viewer_page(doc_id: int):
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    auth_context = g.auth_context
    display_name = _resolve_display_name(db_session, auth_context)

    doc = _get_document_with_access(db_session, auth_context, doc_id)
    if doc is None:
        if _document_exists(db_session, doc_id):
            return render_template(
                "document_viewer.html",
                username=auth_context.core_user.username,
                display_name=display_name,
                role=auth_context.core_user.role,
                document=None,
                error_message="You do not have access to this document.",
                status_code=403,
            ), 403

        return render_template(
            "document_viewer.html",
            username=auth_context.core_user.username,
            display_name=display_name,
            role=auth_context.core_user.role,
            document=None,
            error_message="Document not found.",
            status_code=404,
        ), 404

    requires_password = bool(doc["IsPasswordProtected"])
    password_error = None
    password_verified = not requires_password

    if requires_password:
        if request.method == "POST":
            candidate_password = str(request.form.get("document_password") or "")
            if not candidate_password:
                password_error = "Please provide the document password."
            elif _verify_document_password(db_session, doc_id, candidate_password):
                password_verified = True
            else:
                password_error = "Invalid document password."
        else:
            password_verified = False

    return render_template(
        "document_viewer.html",
        username=auth_context.core_user.username,
        display_name=display_name,
        role=auth_context.core_user.role,
        document=doc,
        requires_password=(requires_password and not password_verified),
        password_error=password_error,
        can_edit=bool(doc.get("CanEdit", False)),
        can_delete=bool(doc.get("CanDelete", False)),
        status_code=200,
    )


@bp.route("/api/members", methods=["POST"])
@login_required(admin_only=True)
def create_member():
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    auth_context = g.auth_context
    data = _payload()

    username = str(data.get("user") or data.get("username") or "").strip()
    password = str(data.get("password") or "")
    role = str(data.get("role") or "Regular").strip().title()
    groups = data.get("groups") or ["default"]

    # User table attributes
    name = str(data.get("name") or "").strip()
    email = str(data.get("email") or "").strip()
    contact_number = str(data.get("contact_number") or "").strip()
    age = data.get("age")
    role_id = data.get("role_id")
    organization_id = data.get("organization_id")
    account_status = str(data.get("account_status") or "Active").strip()

    if isinstance(groups, str):
        groups = [groups]

    if role not in {"Admin", "Regular"}:
        return jsonify({"error": "role must be Admin or Regular"}), 400

    if not username or not password or not name or not email:
        return jsonify({"error": "username, password, name, and email are required"}), 400

    # Validate numeric fields
    try:
        if age is not None:
            age = int(age)
        if role_id is not None:
            role_id = int(role_id)
        if organization_id is not None:
            organization_id = int(organization_id)
    except (TypeError, ValueError):
        return jsonify({"error": "age, role_id, and organization_id must be integers"}), 400

    try:
        existing_core_user = (
            db_session.query(CoreUser)
            .filter(CoreUser.username == username)
            .one_or_none()
        )
        if existing_core_user is not None:
            if existing_core_user.is_active:
                return jsonify({"error": "username already exists"}), 409

            # Handle legacy rows from prior soft-deletes where username was not archived.
            existing_core_user.username = _archived_username(
                existing_core_user.username,
                existing_core_user.id,
            )
            db_session.flush()

        existing_user_password = db_session.execute(
            text(
                """
                SELECT `UserID`, `IsActive`
                FROM `UserPasswords`
                WHERE `LoginUsername` = :login_username
                """
            ),
            {"login_username": username},
        ).mappings().first()

        if existing_user_password is not None:
            if bool(existing_user_password["IsActive"]):
                return jsonify({"error": "username already exists"}), 409

            # Legacy cleanup for stale inactive credential rows.
            db_session.execute(
                text("DELETE FROM `UserPasswords` WHERE `LoginUsername` = :login_username"),
                {"login_username": username},
            )

        # 1. Create new project user (Users table)
        next_user_id = next_numeric_id(db_session, "Users", "UserID")
        
        db_session.execute(
            text("""
                INSERT INTO `Users` (
                    `UserID`, `Name`, `Email`, `ContactNumber`, `Age`,
                    `RoleID`, `OrganizationID`, `AccountStatus`
                )
                VALUES (
                    :user_id, :name, :email, :contact_number, :age,
                    :role_id, :org_id, :status
                )
            """)
            ,
            {
                "user_id": next_user_id,
                "name": name,
                "email": email,
                "contact_number": contact_number,
                "age": age,
                "role_id": role_id,
                "org_id": organization_id,
                "status": account_status,
            },
        )

        password_hash = generate_password_hash(password)

        # 2. Create CoreUser (authentication context)
        user = CoreUser(
            username=username,
            password_hash=password_hash,
            role=role,
            is_active=True,
        )
        db_session.add(user)
        db_session.flush()

        # 3. Link CoreUser to project user
        db_session.add(
            CoreMemberLink(
                core_user_id=user.id,
                project_user_id=next_user_id,
            )
        )

        # 4. Store login credentials for project user accounts.
        db_session.execute(
            text(
                """
                INSERT INTO `UserPasswords` (
                    `UserID`, `LoginUsername`, `PasswordHash`, `IsActive`, `CreatedAt`, `LastModifiedAt`
                )
                VALUES (
                    :user_id, :login_username, :password_hash, 1, :created_at, :last_modified_at
                )
                """
            ),
            {
                "user_id": next_user_id,
                "login_username": username,
                "password_hash": password_hash,
                "created_at": datetime.utcnow(),
                "last_modified_at": datetime.utcnow(),
            },
        )

        # 5. Add group memberships
        for group_name in groups:
            db_session.add(
                CoreGroupMembership(core_user_id=user.id, group_name=str(group_name).strip())
            )

        log_audit_event(
            db_session=db_session,
            action="create_member",
            entity="Users",
            entity_id=str(next_user_id),
            status="SUCCESS",
            actor_core_user_id=auth_context.core_user.id,
            session_token=g.session_token,
            details={
                "created_username": username,
                "core_user_id": user.id,
                "project_user_id": next_user_id,
                "name": name,
                "email": email,
            },
        )

        db_session.commit()
        return jsonify({
            "message": "Member created",
            "core_user_id": user.id,
            "project_user_id": next_user_id,
        }), 201
    except IntegrityError as e:
        db_session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 409
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500


@bp.route("/api/members/<int:core_user_id>", methods=["DELETE"])
@login_required(admin_only=True)
def delete_member(core_user_id: int):
    db_session = g.db_session
    auth_context = g.auth_context

    target = (
        db_session.query(CoreUser)
        .filter(CoreUser.id == core_user_id, CoreUser.is_active.is_(True))
        .one_or_none()
    )
    if target is None:
        return jsonify({"error": "Member not found"}), 404

    if target.id == auth_context.core_user.id:
        return jsonify({"error": "Admin cannot delete currently logged-in account"}), 400

    # Get the project user ID from the link
    member_link = (
        db_session.query(CoreMemberLink)
        .filter(CoreMemberLink.core_user_id == target.id)
        .one_or_none()
    )
    project_user_id = member_link.project_user_id if member_link else None

    # 1. Deactivate all sessions
    db_session.query(CoreSession).filter(CoreSession.core_user_id == target.id).update(
        {CoreSession.is_active: False}
    )

    # 2. Delete group memberships
    db_session.query(CoreGroupMembership).filter(
        CoreGroupMembership.core_user_id == target.id
    ).delete()

    # 3. Delete member link
    db_session.query(CoreMemberLink).filter(CoreMemberLink.core_user_id == target.id).delete()

    # 4. Deactivate core user and archive username for future reuse.
    original_username = target.username
    target.username = _archived_username(original_username, target.id)
    target.is_active = False

    # 5. Delete project credentials and user row from project tables (if linked)
    if project_user_id is not None:
        db_session.execute(
            text("DELETE FROM `UserPasswords` WHERE `UserID` = :user_id"),
            {"user_id": project_user_id},
        )
        db_session.execute(
            text("DELETE FROM `Users` WHERE `UserID` = :user_id"),
            {"user_id": project_user_id},
        )

    log_audit_event(
        db_session=db_session,
        action="delete_member",
        entity="Users",
        entity_id=str(project_user_id) if project_user_id else str(target.id),
        status="SUCCESS",
        actor_core_user_id=auth_context.core_user.id,
        session_token=g.session_token,
        details={
            "deleted_username": original_username,
            "archived_username": target.username,
            "project_user_id": project_user_id,
        },
    )

    db_session.commit()
    return jsonify({"message": "Member deleted successfully"})


@bp.route("/api/documents", methods=["GET"])
@login_required()
def list_documents():
    try:
        ready, response, status_code = _project_tables_ready()
        if not ready:
            return response, status_code

        db_session = g.db_session
        auth_context = g.auth_context
        limit = min(max(int(request.args.get("limit", 30)), 1), 100)

        docs = _list_accessible_documents(db_session, auth_context, limit)
        return jsonify({"documents": docs})

    except Exception as e:
        return jsonify({"error": f"Failed to retrieve documents: {str(e)}"}), 500


@bp.route("/api/documents/<int:doc_id>", methods=["GET"])
@login_required()
def get_document(doc_id: int):
    try:
        ready, response, status_code = _project_tables_ready()
        if not ready:
            return response, status_code

        db_session = g.db_session
        auth_context = g.auth_context

        doc = _get_document_with_access(db_session, auth_context, doc_id)
        if doc is None:
            if _document_exists(db_session, doc_id):
                return jsonify({"error": "Access denied for this document"}), 403
            return jsonify({"error": "Document not found"}), 404

        return jsonify({"document": doc})

    except Exception as e:
        return jsonify({"error": f"Failed to retrieve document: {str(e)}"}), 500


@bp.route("/api/documents", methods=["POST"])
@login_required()
def create_document():
    try:
        ready, response, status_code = _project_tables_ready()
        if not ready:
            return response, status_code

        db_session = g.db_session
        auth_context = g.auth_context
        data = _payload()

        # Regular users can only create in their own organization and as themselves as owner
        # Admins can create for any organization/owner
        if auth_context.core_user.role != "Admin":
            provided_org_id = int(data.get("OrganizationID", 0))
            provided_owner_id = int(data.get("OwnerUserID", 0))

            if provided_org_id != auth_context.project_organization_id:
                return jsonify({"error": "Regular users can only create documents in their own organization"}), 403

            if provided_owner_id != auth_context.project_user_id:
                return jsonify({"error": "Regular users can only create documents as themselves"}), 403

            # Force their org and user ID
            data["OrganizationID"] = auth_context.project_organization_id
            data["OwnerUserID"] = auth_context.project_user_id

        required = ["DocName", "OwnerUserID", "OrganizationID"]
        missing = [name for name in required if name not in data]
        if missing:
            return jsonify({"error": "Missing required fields", "missing": missing}), 400

        is_password_protected = _as_bool(data.get("IsPasswordProtected", False), False)
        document_password = _extract_document_password(data)
        if is_password_protected and (document_password is None or not document_password.strip()):
            return jsonify({"error": "DocumentPassword is required when IsPasswordProtected is true"}), 400

        now = datetime.utcnow()
        new_doc_id = next_numeric_id(db_session, "Documents", "DocID")
        generated_file_path = f"/secure/storage/doc_{new_doc_id}.pdf"

        insert_sql = text(
            """
            INSERT INTO `Documents` (
                `DocID`, `DocName`, `DocSize`, `NumberOfPages`, `FilePath`,
                `ConfidentialityLevel`, `IsPasswordProtected`, `OwnerUserID`,
                `OrganizationID`, `CreatedAt`, `LastModifiedAt`
            )
            VALUES (
                :doc_id, :doc_name, :doc_size, :num_pages, :file_path,
                :conf_level, :protected, :owner_user_id,
                :organization_id, :created_at, :last_modified_at
            )
            """
        )

        params = {
            "doc_id": new_doc_id,
            "doc_name": str(data["DocName"]),
            "doc_size": int(data.get("DocSize", 1024)),
            "num_pages": int(data.get("NumberOfPages", 1)),
            "file_path": generated_file_path,
            "conf_level": str(data.get("ConfidentialityLevel", "Confidentiality Level I")),
            "protected": 1 if is_password_protected else 0,
            "owner_user_id": int(data["OwnerUserID"]),
            "organization_id": int(data["OrganizationID"]),
            "created_at": now,
            "last_modified_at": now,
        }

        db_session.execute(insert_sql, params)

        if is_password_protected and document_password is not None:
            db_session.execute(
                text(
                    """
                    INSERT INTO `DocPasswords` (`DocID`, `PasswordHash`, `CreatedAt`, `LastModifiedAt`)
                    VALUES (:doc_id, :password_hash, :created_at, :last_modified_at)
                    """
                ),
                {
                    "doc_id": new_doc_id,
                    "password_hash": generate_password_hash(document_password),
                    "created_at": now,
                    "last_modified_at": now,
                },
            )

        log_audit_event(
            db_session=db_session,
            action="create_document",
            entity="Documents",
            entity_id=str(new_doc_id),
            status="SUCCESS",
            actor_core_user_id=auth_context.core_user.id,
            session_token=g.session_token,
            details={
                "doc_name": params["doc_name"],
                "organization_id": params["organization_id"],
                "owner_user_id": params["owner_user_id"],
                "password_protected": is_password_protected,
            },
        )

        db_session.commit()
        return jsonify({"message": "Document created", "DocID": new_doc_id}), 201

    except IntegrityError as e:
        db_session.rollback()
        return jsonify({"error": f"Database integrity error: {str(e.orig)}"}), 409
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": f"Failed to create document: {str(e)}"}), 500


@bp.route("/api/documents/<int:doc_id>", methods=["PUT"])
@login_required()
def update_document(doc_id: int):
    try:
        ready, response, status_code = _project_tables_ready()
        if not ready:
            return response, status_code

        db_session = g.db_session
        auth_context = g.auth_context
        data = _payload()

        current = _get_document_with_access(db_session, auth_context, doc_id)
        if current is None:
            if _document_exists(db_session, doc_id):
                return jsonify({"error": "Access denied for this document"}), 403
            return jsonify({"error": "Document not found"}), 404

        if not bool(current.get("CanEdit", False)):
            return jsonify({"error": "You do not have edit access to this document"}), 403

        is_password_protected = _as_bool(data.get("IsPasswordProtected", current["IsPasswordProtected"]), bool(current["IsPasswordProtected"]))
        document_password = _extract_document_password(data)
        has_password_update = document_password is not None
        if has_password_update and not str(document_password).strip():
            return jsonify({"error": "DocumentPassword cannot be empty"}), 400

        if is_password_protected and not has_password_update:
            existing_password = db_session.execute(
                text("SELECT 1 FROM `DocPasswords` WHERE `DocID` = :doc_id"),
                {"doc_id": doc_id},
            ).first()
            if existing_password is None:
                return jsonify({"error": "DocumentPassword is required when password protection is enabled"}), 400

        update_columns = {
            "DocName": data.get("DocName", current["DocName"]),
            "DocSize": int(data.get("DocSize", current["DocSize"])),
            "NumberOfPages": int(data.get("NumberOfPages", current["NumberOfPages"])),
            "FilePath": data.get("FilePath", current["FilePath"]),
            "ConfidentialityLevel": data.get("ConfidentialityLevel", current["ConfidentialityLevel"]),
            "IsPasswordProtected": 1 if is_password_protected else 0,
            "OwnerUserID": int(data.get("OwnerUserID", current["OwnerUserID"])),
            "OrganizationID": int(data.get("OrganizationID", current["OrganizationID"])),
            "LastModifiedAt": datetime.utcnow(),
        }

        db_session.execute(
            text(
                """
                UPDATE `Documents`
                SET `DocName` = :DocName,
                    `DocSize` = :DocSize,
                    `NumberOfPages` = :NumberOfPages,
                    `FilePath` = :FilePath,
                    `ConfidentialityLevel` = :ConfidentialityLevel,
                    `IsPasswordProtected` = :IsPasswordProtected,
                    `OwnerUserID` = :OwnerUserID,
                    `OrganizationID` = :OrganizationID,
                    `LastModifiedAt` = :LastModifiedAt
                WHERE `DocID` = :doc_id
                """
            ),
            {**update_columns, "doc_id": doc_id},
        )

        if is_password_protected:
            if has_password_update and document_password is not None:
                db_session.execute(
                    text(
                        """
                        INSERT INTO `DocPasswords` (`DocID`, `PasswordHash`, `CreatedAt`, `LastModifiedAt`)
                        VALUES (:doc_id, :password_hash, :created_at, :last_modified_at)
                        ON DUPLICATE KEY UPDATE
                            `PasswordHash` = VALUES(`PasswordHash`),
                            `LastModifiedAt` = VALUES(`LastModifiedAt`)
                        """
                    ),
                    {
                        "doc_id": doc_id,
                        "password_hash": generate_password_hash(document_password),
                        "created_at": datetime.utcnow(),
                        "last_modified_at": datetime.utcnow(),
                    },
                )
        else:
            db_session.execute(
                text("DELETE FROM `DocPasswords` WHERE `DocID` = :doc_id"),
                {"doc_id": doc_id},
            )

        log_audit_event(
            db_session=db_session,
            action="update_document",
            entity="Documents",
            entity_id=str(doc_id),
            status="SUCCESS",
            actor_core_user_id=auth_context.core_user.id,
            session_token=g.session_token,
            details={"updated_fields": list(data.keys())},
        )

        db_session.commit()
        return jsonify({"message": "Document updated", "DocID": doc_id})

    except IntegrityError as e:
        db_session.rollback()
        return jsonify({"error": f"Database integrity error: {str(e.orig)}"}), 409
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": f"Failed to update document: {str(e)}"}), 500


@bp.route("/api/documents/<int:doc_id>", methods=["DELETE"])
@login_required()
def delete_document(doc_id: int):
    try:
        ready, response, status_code = _project_tables_ready()
        if not ready:
            return response, status_code

        db_session = g.db_session
        auth_context = g.auth_context

        # Check permission to delete: admin can delete any, others need Delete permission or ownership
        if auth_context.core_user.role != "Admin":
            current = _get_document_with_access(db_session, auth_context, doc_id)
            if current is None:
                if _document_exists(db_session, doc_id):
                    return jsonify({"error": "Access denied for this document"}), 403
                return jsonify({"error": "Document not found"}), 404
            
            if not current.get("CanDelete", False) and not current.get("IsOwner", False):
                return jsonify({"error": "You do not have permission to delete this document"}), 403

        # Verify document exists for deletion
        if not _document_exists(db_session, doc_id):
            return jsonify({"error": "Document not found"}), 404

        # Fetch document info for audit log
        doc_row = db_session.execute(
            text("SELECT `DocName`, `OrganizationID` FROM `Documents` WHERE `DocID` = :doc_id"),
            {"doc_id": doc_id},
        ).mappings().first()

        db_session.execute(
            text("DELETE FROM `DocPasswords` WHERE `DocID` = :doc_id"),
            {"doc_id": doc_id},
        )

        db_session.execute(
            text("DELETE FROM `Documents` WHERE `DocID` = :doc_id"),
            {"doc_id": doc_id},
        )

        log_audit_event(
            db_session=db_session,
            action="delete_document",
            entity="Documents",
            entity_id=str(doc_id),
            status="SUCCESS",
            actor_core_user_id=auth_context.core_user.id,
            session_token=g.session_token,
            details={
                "doc_name": doc_row["DocName"] if doc_row else None,
                "organization_id": doc_row["OrganizationID"] if doc_row else None,
            },
        )

        db_session.commit()
        return jsonify({"message": "Document deleted", "DocID": doc_id})

    except IntegrityError as e:
        db_session.rollback()
        return jsonify({"error": f"Database integrity error: {str(e.orig)}"}), 409
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": f"Failed to delete document: {str(e)}"}), 500


@bp.route("/api/permissions/grant", methods=["POST"])
@login_required()
def grant_permission():
    try:
        ready, response, status_code = _project_tables_ready()
        if not ready:
            return response, status_code

        db_session = g.db_session
        auth_context = g.auth_context
        data = _payload()

        doc_id = data.get("doc_id")
        user_id = data.get("user_id")
        access_type = str(data.get("access_type", "View")).title()

        if access_type not in {"View", "Edit", "Delete"}:
            return jsonify({"error": "access_type must be View, Edit, or Delete"}), 400

        if doc_id is None or user_id is None:
            return jsonify({"error": "doc_id and user_id are required"}), 400

        doc_id = int(doc_id)
        user_id = int(user_id)

        document_row = db_session.execute(
            text(
                """
                SELECT `DocID`, `DocName`, `OwnerUserID`, `OrganizationID`
                FROM `Documents`
                WHERE `DocID` = :doc_id
                """
            ),
            {"doc_id": doc_id},
        ).mappings().first()

        if document_row is None:
            return jsonify({"error": "Document not found"}), 404

        is_admin = auth_context.core_user.role == "Admin"
        is_owner = (
            auth_context.project_user_id is not None
            and int(auth_context.project_user_id) == int(document_row["OwnerUserID"])
        )
        if not (is_admin or is_owner):
            return jsonify({"error": "Only the document owner or an admin can grant access"}), 403

        if int(document_row["OwnerUserID"]) == user_id:
            return jsonify({"error": "The owner already has full access"}), 400

        target_user = db_session.execute(
            text(
                """
                SELECT `UserID`, `OrganizationID`, `AccountStatus`
                FROM `Users`
                WHERE `UserID` = :user_id
                """
            ),
            {"user_id": user_id},
        ).mappings().first()
        if target_user is None:
            return jsonify({"error": "Target user not found"}), 404

        if int(target_user["OrganizationID"]) != int(document_row["OrganizationID"]):
            return jsonify({"error": "Access can only be granted to users in the same organization"}), 403

        existing = db_session.execute(
            text(
                """
                SELECT `PermissionID`
                FROM `Permissions`
                WHERE `DocID` = :doc_id AND `UserID` = :user_id AND `AccessType` = :access_type
                """
            ),
            {"doc_id": doc_id, "user_id": user_id, "access_type": access_type},
        ).first()

        if existing is not None:
            return jsonify({"message": "Permission already exists", "PermissionID": existing[0]}), 200

        permission_id = next_numeric_id(db_session, "Permissions", "PermissionID")
        db_session.execute(
            text(
                """
                INSERT INTO `Permissions` (`PermissionID`, `DocID`, `UserID`, `AccessType`, `GrantedAt`)
                VALUES (:permission_id, :doc_id, :user_id, :access_type, :granted_at)
                """
            ),
            {
                "permission_id": permission_id,
                "doc_id": doc_id,
                "user_id": user_id,
                "access_type": access_type,
                "granted_at": datetime.utcnow(),
            },
        )

        log_audit_event(
            db_session=db_session,
            action="grant_permission",
            entity="Permissions",
            entity_id=str(permission_id),
            status="SUCCESS",
            actor_core_user_id=auth_context.core_user.id,
            session_token=g.session_token,
            details={
                "doc_id": doc_id,
                "doc_owner_user_id": int(document_row["OwnerUserID"]),
                "user_id": user_id,
                "access_type": access_type,
            },
        )

        db_session.commit()
        return jsonify({"message": "Permission granted", "PermissionID": permission_id}), 201

    except (TypeError, ValueError) as e:
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400
    except IntegrityError as e:
        db_session.rollback()
        return jsonify({"error": f"Database integrity error: {str(e.orig)}"}), 409
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": f"Failed to grant permission: {str(e)}"}), 500


@bp.route("/api/documents/<int:doc_id>/permissions", methods=["GET"])
@login_required()
def list_document_permissions(doc_id: int):
    try:
        ready, response, status_code = _project_tables_ready()
        if not ready:
            return response, status_code

        db_session = g.db_session
        auth_context = g.auth_context

        document_row = db_session.execute(
            text(
                """
                SELECT `DocID`, `DocName`, `OwnerUserID`, `OrganizationID`
                FROM `Documents`
                WHERE `DocID` = :doc_id
                """
            ),
            {"doc_id": doc_id},
        ).mappings().first()
        if document_row is None:
            return jsonify({"error": "Document not found"}), 404

        is_admin = auth_context.core_user.role == "Admin"
        is_owner = (
            auth_context.project_user_id is not None
            and int(auth_context.project_user_id) == int(document_row["OwnerUserID"])
        )
        if not (is_admin or is_owner):
            return jsonify({"error": "Only the document owner or an admin can view access settings"}), 403

        permission_rows = db_session.execute(
            text(
                """
                SELECT p.`PermissionID`, p.`DocID`, p.`UserID`, p.`AccessType`, p.`GrantedAt`,
                       u.`Name` AS `UserName`, u.`Email` AS `UserEmail`
                FROM `Permissions` p
                LEFT JOIN `Users` u ON u.`UserID` = p.`UserID`
                WHERE p.`DocID` = :doc_id
                ORDER BY p.`GrantedAt` DESC, p.`PermissionID` DESC
                """
            ),
            {"doc_id": doc_id},
        ).mappings().all()

        member_rows = db_session.execute(
            text(
                """
                SELECT `UserID`, `Name`, `Email`, `AccountStatus`
                FROM `Users`
                WHERE `OrganizationID` = :organization_id
                  AND `UserID` <> :owner_user_id
                  AND `AccountStatus` = 'Active'
                ORDER BY `UserID`
                LIMIT 500
                """
            ),
            {
                "organization_id": int(document_row["OrganizationID"]),
                "owner_user_id": int(document_row["OwnerUserID"]),
            },
        ).mappings().all()

        return jsonify(
            {
                "document": {
                    "DocID": int(document_row["DocID"]),
                    "DocName": str(document_row["DocName"]),
                    "OwnerUserID": int(document_row["OwnerUserID"]),
                    "OrganizationID": int(document_row["OrganizationID"]),
                },
                "permissions": [
                    {
                        "PermissionID": int(row["PermissionID"]),
                        "DocID": int(row["DocID"]),
                        "UserID": int(row["UserID"]),
                        "UserName": row["UserName"],
                        "UserEmail": row["UserEmail"],
                        "AccessType": row["AccessType"],
                        "GrantedAt": _to_iso(row["GrantedAt"]),
                    }
                    for row in permission_rows
                ],
                "manageable_users": [
                    {
                        "UserID": int(row["UserID"]),
                        "Name": row["Name"],
                        "Email": row["Email"],
                        "AccountStatus": row["AccountStatus"],
                    }
                    for row in member_rows
                ],
            }
        )

    except Exception as e:
        return jsonify({"error": f"Failed to load document permissions: {str(e)}"}), 500


@bp.route("/api/permissions/revoke", methods=["POST"])
@login_required()
def revoke_permission():
    try:
        ready, response, status_code = _project_tables_ready()
        if not ready:
            return response, status_code

        db_session = g.db_session
        auth_context = g.auth_context
        data = _payload()

        permission_id = data.get("permission_id")
        if permission_id is None:
            return jsonify({"error": "permission_id is required"}), 400

        permission_id = int(permission_id)

        permission_row = db_session.execute(
            text(
                """
                SELECT p.`PermissionID`, p.`DocID`, p.`UserID`, p.`AccessType`,
                       d.`OwnerUserID`, d.`OrganizationID`
                FROM `Permissions` p
                JOIN `Documents` d ON d.`DocID` = p.`DocID`
                WHERE p.`PermissionID` = :permission_id
                """
            ),
            {"permission_id": permission_id},
        ).mappings().first()

        if permission_row is None:
            return jsonify({"error": "Permission not found"}), 404

        is_admin = auth_context.core_user.role == "Admin"
        is_owner = (
            auth_context.project_user_id is not None
            and int(auth_context.project_user_id) == int(permission_row["OwnerUserID"])
        )
        if not (is_admin or is_owner):
            return jsonify({"error": "Only the document owner or an admin can revoke access"}), 403

        db_session.execute(
            text("DELETE FROM `Permissions` WHERE `PermissionID` = :permission_id"),
            {"permission_id": permission_id},
        )

        log_audit_event(
            db_session=db_session,
            action="revoke_permission",
            entity="Permissions",
            entity_id=str(permission_id),
            status="SUCCESS",
            actor_core_user_id=auth_context.core_user.id,
            session_token=g.session_token,
            details={
                "doc_id": int(permission_row["DocID"]),
                "user_id": int(permission_row["UserID"]),
                "access_type": permission_row["AccessType"],
            },
        )

        db_session.commit()
        return jsonify({"message": "Permission revoked", "PermissionID": permission_id})

    except (TypeError, ValueError) as e:
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": f"Failed to revoke permission: {str(e)}"}), 500


@bp.route("/api/audit/logs", methods=["GET"])
@login_required(admin_only=True)
def list_audit_logs():
    db_session = g.db_session
    limit = min(max(int(request.args.get("limit", 50)), 1), 500)

    rows = db_session.execute(
        text(
            """
            SELECT `id`, `actor_core_user_id`, `session_token`, `action`, `entity`,
                   `entity_id`, `status`, `details_json`, `created_at`
            FROM `CoreAuditLogs`
            ORDER BY `created_at` DESC
            LIMIT :limit
            """
        ),
        {"limit": limit},
    ).mappings().all()

    return jsonify(
        {
            "audit_logs": [
                {
                    "id": row["id"],
                    "actor_core_user_id": row["actor_core_user_id"],
                    "session_token": row["session_token"],
                    "action": row["action"],
                    "entity": row["entity"],
                    "entity_id": row["entity_id"],
                    "status": row["status"],
                    "details_json": row["details_json"],
                    "created_at": _to_iso(row["created_at"]),
                }
                for row in rows
            ]
        }
    )


@bp.route("/api/audit/unauthorized", methods=["GET"])
@login_required(admin_only=True)
def detect_unauthorized_changes():
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    state_row = db_session.get(CoreAuditState, "tracking_started_at")
    tracking_started_at = datetime.utcnow()

    if state_row is not None:
        try:
            tracking_started_at = datetime.fromisoformat(state_row.state_value.replace("Z", "+00:00"))
            if tracking_started_at.tzinfo is not None:
                tracking_started_at = tracking_started_at.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            tracking_started_at = datetime.utcnow()

    suspicious_rows = db_session.execute(
        text(
            """
            SELECT d.`DocID`, d.`LastModifiedAt`, a.last_audit_at
            FROM `Documents` d
            LEFT JOIN (
                SELECT CAST(`entity_id` AS UNSIGNED) AS doc_id, MAX(`created_at`) AS last_audit_at
                FROM `CoreAuditLogs`
                WHERE `entity` = 'Documents'
                  AND `action` IN ('create_document', 'update_document', 'delete_document')
                  AND `status` = 'SUCCESS'
                GROUP BY CAST(`entity_id` AS UNSIGNED)
            ) a ON a.doc_id = d.`DocID`
            WHERE d.`LastModifiedAt` >= :tracking_started_at
              AND (a.last_audit_at IS NULL OR a.last_audit_at < d.`LastModifiedAt`)
            ORDER BY d.`LastModifiedAt` DESC
            LIMIT 200
            """
        ),
        {"tracking_started_at": tracking_started_at},
    ).mappings().all()

    return jsonify(
        {
            "tracking_started_at": tracking_started_at.isoformat(),
            "suspicious_documents": [
                {
                    "DocID": row["DocID"],
                    "LastModifiedAt": _to_iso(row["LastModifiedAt"]),
                    "LastAuthorizedAudit": _to_iso(row["last_audit_at"]),
                }
                for row in suspicious_rows
            ],
        }
    )


@bp.route("/api/optimization/explain/documents", methods=["GET"])
@login_required(admin_only=True)
def explain_documents_query():
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    org_id = request.args.get("org_id")

    if org_id is None:
        explain_rows = db_session.execute(
            text(
                """
                EXPLAIN SELECT *
                FROM `Documents`
                ORDER BY `LastModifiedAt` DESC
                LIMIT 50
                """
            )
        ).mappings().all()
    else:
        explain_rows = db_session.execute(
            text(
                """
                EXPLAIN SELECT *
                FROM `Documents`
                WHERE `OrganizationID` = :org_id
                ORDER BY `LastModifiedAt` DESC
                LIMIT 50
                """
            ),
            {"org_id": int(org_id)},
        ).mappings().all()

    return jsonify({"explain": [dict(row) for row in explain_rows]})
