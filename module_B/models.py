from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class CoreUser(Base):
    __tablename__ = "CoreUsers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="Regular")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime, nullable=False, server_default=func.now())


class CoreSession(Base):
    __tablename__ = "CoreSessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    core_user_id: Mapped[int] = mapped_column(ForeignKey("CoreUsers.id"), nullable=False, index=True)
    session_token: Mapped[str] = mapped_column(String(700), unique=True, nullable=False, index=True)
    expires_at: Mapped[DateTime] = mapped_column(DateTime, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime, nullable=False, server_default=func.now())


class CoreMemberLink(Base):
    __tablename__ = "CoreMemberLinks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    core_user_id: Mapped[int] = mapped_column(ForeignKey("CoreUsers.id"), nullable=False, unique=True)
    project_user_id: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime, nullable=False, server_default=func.now())


class CoreGroupMembership(Base):
    __tablename__ = "CoreGroupMemberships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    core_user_id: Mapped[int] = mapped_column(ForeignKey("CoreUsers.id"), nullable=False, index=True)
    group_name: Mapped[str] = mapped_column(String(80), nullable=False)
    created_at: Mapped[DateTime] = mapped_column(DateTime, nullable=False, server_default=func.now())

    __table_args__ = (UniqueConstraint("core_user_id", "group_name", name="uq_core_user_group"),)


class CoreAuditLog(Base):
    __tablename__ = "CoreAuditLogs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_core_user_id: Mapped[int | None] = mapped_column(ForeignKey("CoreUsers.id"), nullable=True, index=True)
    session_token: Mapped[str | None] = mapped_column(String(700), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    entity: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    entity_id: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="SUCCESS", index=True)
    details_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime, nullable=False, server_default=func.now(), index=True)


class CoreAuditState(Base):
    __tablename__ = "CoreAuditState"

    state_key: Mapped[str] = mapped_column(String(100), primary_key=True)
    state_value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[DateTime] = mapped_column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())
