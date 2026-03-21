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


def _document_from_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "DocID": row["DocID"],
        "DocName": row["DocName"],
        "DocSize": row["DocSize"],
        "NumberOfPages": row["NumberOfPages"],
        "FilePath": row["FilePath"],
        "ConfidentialityLevel": row["ConfidentialityLevel"],
        "IsPasswordProtected": bool(row["IsPasswordProtected"]),
        "OwnerUserID": row["OwnerUserID"],
        "OrganizationID": row["OrganizationID"],
        "CreatedAt": _to_iso(row["CreatedAt"]),
        "LastModifiedAt": _to_iso(row["LastModifiedAt"]),
    }


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
        if user is None or not check_password_hash(user.password_hash, password):
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
    elif auth_context.project_user_id is not None:
        member_rows = db_session.execute(
            text(
                """
                SELECT `UserID`, `Name`, `Email`, `OrganizationID`, `AccountStatus`
                FROM `Users`
                WHERE `UserID` = :project_user_id
                """
            ),
            {"project_user_id": auth_context.project_user_id},
        ).mappings().all()
        total_pages = 1
        total_count = len(member_rows)
    else:
        member_rows = []
        total_pages = 1
        total_count = 0

    doc_count_query = "SELECT COUNT(*) FROM `Documents`"
    params_doc: dict[str, Any] = {}
    if auth_context.core_user.role != "Admin" and auth_context.project_organization_id is not None:
        doc_count_query += " WHERE `OrganizationID` = :org_id"
        params_doc["org_id"] = auth_context.project_organization_id

    document_count = int(db_session.execute(text(doc_count_query), params_doc).scalar_one())

    return render_template(
        "dashboard.html",
        username=auth_context.core_user.username,
        role=auth_context.core_user.role,
        members=member_rows,
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

    if auth_context.core_user.role != "Admin" and auth_context.project_user_id != member_id:
        return jsonify({"error": "Insufficient portfolio access"}), 403

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

        # 2. Create CoreUser (authentication)
        user = CoreUser(
            username=username,
            password_hash=generate_password_hash(password),
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

        # 4. Add group memberships
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

    # 4. Deactivate core user
    target.is_active = False

    # 5. Delete project user from Users table (if linked)
    if project_user_id is not None:
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
            "deleted_username": target.username,
            "project_user_id": project_user_id,
        },
    )

    db_session.commit()
    return jsonify({"message": "Member deleted successfully"})


@bp.route("/api/documents", methods=["GET"])
@login_required()
def list_documents():
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    auth_context = g.auth_context
    limit = min(max(int(request.args.get("limit", 30)), 1), 100)

    if auth_context.core_user.role == "Admin":
        rows = db_session.execute(
            text(
                """
                SELECT *
                FROM `Documents`
                ORDER BY `LastModifiedAt` DESC
                LIMIT :limit
                """
            ),
            {"limit": limit},
        ).mappings().all()
    else:
        if auth_context.project_organization_id is None:
            return jsonify({"error": "Current user is not mapped to project member data"}), 403

        rows = db_session.execute(
            text(
                """
                SELECT *
                FROM `Documents`
                WHERE `OrganizationID` = :org_id
                ORDER BY `LastModifiedAt` DESC
                LIMIT :limit
                """
            ),
            {"org_id": auth_context.project_organization_id, "limit": limit},
        ).mappings().all()

    return jsonify({"documents": [_document_from_row(dict(row)) for row in rows]})


@bp.route("/api/documents/<int:doc_id>", methods=["GET"])
@login_required()
def get_document(doc_id: int):
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    auth_context = g.auth_context

    query = "SELECT * FROM `Documents` WHERE `DocID` = :doc_id"
    params = {"doc_id": doc_id}

    if auth_context.core_user.role != "Admin":
        if auth_context.project_organization_id is None:
            return jsonify({"error": "Current user is not mapped to project member data"}), 403
        query += " AND `OrganizationID` = :org_id"
        params["org_id"] = auth_context.project_organization_id

    row = db_session.execute(text(query), params).mappings().first()
    if row is None:
        return jsonify({"error": "Document not found"}), 404

    return jsonify({"document": _document_from_row(dict(row))})


@bp.route("/api/documents", methods=["POST"])
@login_required(admin_only=True)
def create_document():
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    auth_context = g.auth_context
    data = _payload()

    required = ["DocName", "OwnerUserID", "OrganizationID"]
    missing = [name for name in required if name not in data]
    if missing:
        return jsonify({"error": "Missing required fields", "missing": missing}), 400

    now = datetime.utcnow()
    new_doc_id = next_numeric_id(db_session, "Documents", "DocID")

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
        "file_path": str(data.get("FilePath", f"/secure/storage/doc_{new_doc_id}.pdf")),
        "conf_level": str(data.get("ConfidentialityLevel", "Confidentiality Level I")),
        "protected": 1 if bool(data.get("IsPasswordProtected", False)) else 0,
        "owner_user_id": int(data["OwnerUserID"]),
        "organization_id": int(data["OrganizationID"]),
        "created_at": now,
        "last_modified_at": now,
    }

    db_session.execute(insert_sql, params)

    log_audit_event(
        db_session=db_session,
        action="create_document",
        entity="Documents",
        entity_id=str(new_doc_id),
        status="SUCCESS",
        actor_core_user_id=auth_context.core_user.id,
        session_token=g.session_token,
        details={"doc_name": params["doc_name"], "organization_id": params["organization_id"]},
    )

    db_session.commit()
    return jsonify({"message": "Document created", "DocID": new_doc_id}), 201


@bp.route("/api/documents/<int:doc_id>", methods=["PUT"])
@login_required()
def update_document(doc_id: int):
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    auth_context = g.auth_context
    data = _payload()

    current = db_session.execute(
        text("SELECT * FROM `Documents` WHERE `DocID` = :doc_id"),
        {"doc_id": doc_id},
    ).mappings().first()

    if current is None:
        return jsonify({"error": "Document not found"}), 404

    if auth_context.core_user.role != "Admin":
        if auth_context.project_user_id is None:
            return jsonify({"error": "Current user is not mapped to project member data"}), 403
        if int(current["OwnerUserID"]) != int(auth_context.project_user_id):
            return jsonify({"error": "Regular users can only modify their own documents"}), 403

    update_columns = {
        "DocName": data.get("DocName", current["DocName"]),
        "DocSize": int(data.get("DocSize", current["DocSize"])),
        "NumberOfPages": int(data.get("NumberOfPages", current["NumberOfPages"])),
        "FilePath": data.get("FilePath", current["FilePath"]),
        "ConfidentialityLevel": data.get("ConfidentialityLevel", current["ConfidentialityLevel"]),
        "IsPasswordProtected": 1 if bool(data.get("IsPasswordProtected", current["IsPasswordProtected"])) else 0,
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


@bp.route("/api/documents/<int:doc_id>", methods=["DELETE"])
@login_required(admin_only=True)
def delete_document(doc_id: int):
    ready, response, status_code = _project_tables_ready()
    if not ready:
        return response, status_code

    db_session = g.db_session
    auth_context = g.auth_context

    deleted = db_session.execute(
        text("DELETE FROM `Documents` WHERE `DocID` = :doc_id"),
        {"doc_id": doc_id},
    )

    if deleted.rowcount == 0:
        return jsonify({"error": "Document not found"}), 404

    log_audit_event(
        db_session=db_session,
        action="delete_document",
        entity="Documents",
        entity_id=str(doc_id),
        status="SUCCESS",
        actor_core_user_id=auth_context.core_user.id,
        session_token=g.session_token,
        details={},
    )

    db_session.commit()
    return jsonify({"message": "Document deleted", "DocID": doc_id})


@bp.route("/api/permissions/grant", methods=["POST"])
@login_required(admin_only=True)
def grant_permission():
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
        details={"doc_id": doc_id, "user_id": user_id, "access_type": access_type},
    )

    db_session.commit()
    return jsonify({"message": "Permission granted", "PermissionID": permission_id}), 201


@bp.route("/api/permissions/revoke", methods=["POST"])
@login_required(admin_only=True)
def revoke_permission():
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
    deleted = db_session.execute(
        text("DELETE FROM `Permissions` WHERE `PermissionID` = :permission_id"),
        {"permission_id": permission_id},
    )

    if deleted.rowcount == 0:
        return jsonify({"error": "Permission not found"}), 404

    log_audit_event(
        db_session=db_session,
        action="revoke_permission",
        entity="Permissions",
        entity_id=str(permission_id),
        status="SUCCESS",
        actor_core_user_id=auth_context.core_user.id,
        session_token=g.session_token,
        details={},
    )

    db_session.commit()
    return jsonify({"message": "Permission revoked", "PermissionID": permission_id})


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
