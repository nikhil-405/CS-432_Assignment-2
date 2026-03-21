import argparse
import csv
import json
import os
import re
import secrets
import string
import tempfile
from datetime import datetime
from pathlib import Path

from sqlalchemy import text
from werkzeug.security import generate_password_hash

from module_B.database import get_engine, init_core_schema

_USERNAME_SANITIZE = re.compile(r"[^a-z0-9_]+")


def _normalize_username(value: str) -> str:
    normalized = value.strip().lower().replace(" ", "_")
    normalized = _USERNAME_SANITIZE.sub("_", normalized)
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    return normalized


def _fit_username(base: str, suffix: str = "") -> str:
    if len(suffix) >= 80:
        return suffix[-80:]
    return f"{base[: 80 - len(suffix)]}{suffix}"


def _pick_login_username(user_id: int, preferred: list[str], used_usernames: set[str]) -> str:
    for candidate_source in preferred:
        candidate_base = _normalize_username(candidate_source)
        if not candidate_base:
            continue
        candidate = _fit_username(candidate_base)
        if candidate and candidate not in used_usernames:
            return candidate

    fallback_base = f"user_{user_id}"
    fallback = _fit_username(fallback_base)
    if fallback not in used_usernames:
        return fallback

    for index in range(1, 10000):
        suffix = f"_{index}"
        candidate = _fit_username(fallback_base, suffix=suffix)
        if candidate not in used_usernames:
            return candidate

    raise RuntimeError(f"Unable to generate unique login username for UserID={user_id}")


def _generate_temp_password(length: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _sync_core_accounts(connection, now: datetime) -> dict[str, int]:
    created_core_users = 0
    reactivated_core_users = 0
    created_links = 0

    rows = connection.execute(
        text(
            """
            SELECT up.`UserID`, up.`LoginUsername`, up.`PasswordHash`
            FROM `UserPasswords` up
            LEFT JOIN `CoreMemberLinks` cml ON cml.`project_user_id` = up.`UserID`
            WHERE up.`IsActive` = 1
              AND cml.`id` IS NULL
            ORDER BY up.`UserID`
            """
        )
    ).mappings().all()

    for row in rows:
        user_id = int(row["UserID"])
        login_username = str(row["LoginUsername"])
        password_hash = str(row["PasswordHash"])

        core_row = connection.execute(
            text("SELECT `id`, `is_active` FROM `CoreUsers` WHERE `username` = :username"),
            {"username": login_username},
        ).mappings().first()

        if core_row is None:
            connection.execute(
                text(
                    """
                    INSERT INTO `CoreUsers` (`username`, `password_hash`, `role`, `is_active`, `created_at`)
                    VALUES (:username, :password_hash, :role, 1, :created_at)
                    """
                ),
                {
                    "username": login_username,
                    "password_hash": password_hash,
                    "role": "Regular",
                    "created_at": now,
                },
            )
            created_core_users += 1
            core_id = int(connection.execute(text("SELECT LAST_INSERT_ID()")).scalar_one())
        else:
            core_id = int(core_row["id"])
            if not bool(core_row["is_active"]):
                connection.execute(
                    text(
                        """
                        UPDATE `CoreUsers`
                        SET `is_active` = 1,
                            `password_hash` = :password_hash
                        WHERE `id` = :core_id
                        """
                    ),
                    {
                        "password_hash": password_hash,
                        "core_id": core_id,
                    },
                )
                reactivated_core_users += 1

        link_row = connection.execute(
            text("SELECT `id` FROM `CoreMemberLinks` WHERE `project_user_id` = :project_user_id"),
            {"project_user_id": user_id},
        ).first()

        if link_row is None:
            connection.execute(
                text(
                    """
                    INSERT INTO `CoreMemberLinks` (`core_user_id`, `project_user_id`, `created_at`)
                    VALUES (:core_user_id, :project_user_id, :created_at)
                    """
                ),
                {
                    "core_user_id": core_id,
                    "project_user_id": user_id,
                    "created_at": now,
                },
            )
            created_links += 1

    return {
        "created_core_users": created_core_users,
        "reactivated_core_users": reactivated_core_users,
        "created_links": created_links,
    }


def populate_userpasswords(temp_file: str | None = None) -> dict:
    init_core_schema()

    now = datetime.now().astimezone().replace(tzinfo=None)
    report_rows: list[dict[str, str]] = []

    with get_engine().begin() as connection:
        users = connection.execute(
            text("SELECT `UserID`, `Name`, `Email` FROM `Users` ORDER BY `UserID`")
        ).mappings().all()

        existing_rows = connection.execute(
            text("SELECT `UserID`, `LoginUsername`, `IsActive` FROM `UserPasswords`")
        ).mappings().all()
        existing_by_user_id = {int(row["UserID"]): row for row in existing_rows}
        used_usernames = {str(row["LoginUsername"]) for row in existing_rows}

        mapped_rows = connection.execute(
            text(
                """
                SELECT l.`project_user_id` AS `UserID`, u.`username` AS `CoreUsername`
                FROM `CoreMemberLinks` l
                JOIN `CoreUsers` u ON u.`id` = l.`core_user_id`
                """
            )
        ).mappings().all()
        mapped_username_by_user_id = {
            int(row["UserID"]): str(row["CoreUsername"]) for row in mapped_rows
        }

        created_count = 0
        reactivated_count = 0
        existing_count = 0

        for user_row in users:
            user_id = int(user_row["UserID"])
            email = str(user_row.get("Email") or "")
            name = str(user_row.get("Name") or "")

            existing = existing_by_user_id.get(user_id)
            if existing is not None:
                login_username = str(existing["LoginUsername"])
                is_active = bool(existing["IsActive"])
                if is_active:
                    existing_count += 1
                    report_rows.append(
                        {
                            "UserID": str(user_id),
                            "LoginUsername": login_username,
                            "TemporaryPassword": "",
                            "Status": "existing",
                        }
                    )
                    continue

                temp_password = _generate_temp_password()
                connection.execute(
                    text(
                        """
                        UPDATE `UserPasswords`
                        SET `PasswordHash` = :password_hash,
                            `IsActive` = 1,
                            `LastModifiedAt` = :updated_at
                        WHERE `UserID` = :user_id
                        """
                    ),
                    {
                        "password_hash": generate_password_hash(temp_password),
                        "updated_at": now,
                        "user_id": user_id,
                    },
                )
                reactivated_count += 1
                report_rows.append(
                    {
                        "UserID": str(user_id),
                        "LoginUsername": login_username,
                        "TemporaryPassword": temp_password,
                        "Status": "reactivated",
                    }
                )
                continue

            preferred_candidates = []
            core_username = mapped_username_by_user_id.get(user_id)
            if core_username:
                preferred_candidates.append(core_username)
            if email and "@" in email:
                preferred_candidates.append(email.split("@", 1)[0])
            preferred_candidates.append(name)
            preferred_candidates.append(f"user_{user_id}")

            login_username = _pick_login_username(user_id, preferred_candidates, used_usernames)
            used_usernames.add(login_username)

            temp_password = _generate_temp_password()
            connection.execute(
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
                    "user_id": user_id,
                    "login_username": login_username,
                    "password_hash": generate_password_hash(temp_password),
                    "created_at": now,
                    "last_modified_at": now,
                },
            )

            created_count += 1
            report_rows.append(
                {
                    "UserID": str(user_id),
                    "LoginUsername": login_username,
                    "TemporaryPassword": temp_password,
                    "Status": "created",
                }
            )

        core_sync_stats = _sync_core_accounts(connection, now)

    if temp_file:
        output_path = Path(temp_file).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        report_dir = Path(__file__).resolve().parent / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        fd, raw_path = tempfile.mkstemp(
            prefix="userpasswords_seed_", suffix=".csv", dir=str(report_dir)
        )
        os.close(fd)
        output_path = Path(raw_path)

    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["UserID", "LoginUsername", "TemporaryPassword", "Status"],
        )
        writer.writeheader()
        writer.writerows(report_rows)

    return {
        "output_file": str(output_path),
        "total_users": len(report_rows),
        "created": created_count,
        "reactivated": reactivated_count,
        "existing": existing_count,
        **core_sync_stats,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Populate UserPasswords from Users and export temporary credentials CSV."
    )
    parser.add_argument(
        "--temp-file",
        dest="temp_file",
        default=None,
        help="Optional path for generated CSV output.",
    )
    args = parser.parse_args()

    result = populate_userpasswords(temp_file=args.temp_file)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
    