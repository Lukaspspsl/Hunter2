"""SQLAlchemy models for Hunter 2.

Extends Hunter 1.0 schema with: Program, ToolExecution, LLMSession,
and adds in_scope/oos_reason/program_id on Subdomain.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


class Base(DeclarativeBase):
    pass


class Program(Base):
    """Bug bounty program — top-level scope container."""

    __tablename__ = "programs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    platform: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    aggressiveness: Mapped[str] = mapped_column(String(20), default="passive")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    subdomains: Mapped[list["Subdomain"]] = relationship(back_populates="program")
    scans: Mapped[list["Scan"]] = relationship(back_populates="program_obj")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="running")
    target_source: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    log_file: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    project: Mapped[str] = mapped_column(String(100), default="default", index=True)
    program_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("programs.id"), nullable=True
    )
    triggered_by: Mapped[str] = mapped_column(String(20), default="manual")
    aggressiveness: Mapped[str] = mapped_column(String(20), default="passive")

    program_obj: Mapped[Optional["Program"]] = relationship(back_populates="scans")
    subdomains: Mapped[list["Subdomain"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    secrets: Mapped[list["Secret"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    tool_executions: Mapped[list["ToolExecution"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Subdomain(Base):
    __tablename__ = "subdomains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    program_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("programs.id"), nullable=True, index=True
    )
    domain: Mapped[str] = mapped_column(String(500), index=True)
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_new: Mapped[bool] = mapped_column(Boolean, default=True)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    oos_reason: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="subdomains")
    program: Mapped[Optional["Program"]] = relationship(back_populates="subdomains")
    ports: Mapped[list["Port"]] = relationship(
        back_populates="subdomain", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="subdomain", cascade="all, delete-orphan"
    )
    technologies: Mapped[list["Technology"]] = relationship(
        back_populates="subdomain", cascade="all, delete-orphan"
    )
    screenshots: Mapped[list["Screenshot"]] = relationship(
        back_populates="subdomain", cascade="all, delete-orphan"
    )
    directories: Mapped[list["Directory"]] = relationship(
        back_populates="subdomain", cascade="all, delete-orphan"
    )


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subdomain_id: Mapped[int] = mapped_column(ForeignKey("subdomains.id"))
    port_number: Mapped[int] = mapped_column(Integer)
    service: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    state: Mapped[str] = mapped_column(String(50), default="open")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    subdomain: Mapped["Subdomain"] = relationship(back_populates="ports")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subdomain_id: Mapped[int] = mapped_column(ForeignKey("subdomains.id"))
    template_id: Mapped[str] = mapped_column(String(200))
    name: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(50))
    matched_at: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    found_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    subdomain: Mapped["Subdomain"] = relationship(back_populates="vulnerabilities")


class Technology(Base):
    __tablename__ = "technologies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subdomain_id: Mapped[int] = mapped_column(ForeignKey("subdomains.id"))
    name: Mapped[str] = mapped_column(String(200))
    version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    subdomain: Mapped["Subdomain"] = relationship(back_populates="technologies")


class Secret(Base):
    __tablename__ = "secrets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    source: Mapped[str] = mapped_column(String(100))
    file_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    secret_type: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    commit_hash: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    repository: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    line_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    secret_preview: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    found_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan: Mapped["Scan"] = relationship(back_populates="secrets")


class Screenshot(Base):
    __tablename__ = "screenshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subdomain_id: Mapped[int] = mapped_column(ForeignKey("subdomains.id"))
    file_path: Mapped[str] = mapped_column(String(1000))
    response_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    taken_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    subdomain: Mapped["Subdomain"] = relationship(back_populates="screenshots")


class Directory(Base):
    __tablename__ = "directories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subdomain_id: Mapped[int] = mapped_column(ForeignKey("subdomains.id"))
    path: Mapped[str] = mapped_column(String(1000))
    status_code: Mapped[int] = mapped_column(Integer)
    content_length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    found_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    subdomain: Mapped["Subdomain"] = relationship(back_populates="directories")


class ToolExecution(Base):
    """Audit trail for every tool invocation."""

    __tablename__ = "tool_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scans.id"), nullable=True, index=True
    )
    program: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    target: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(100), index=True)
    args: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    result_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_output_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(20), default="manual")
    llm_reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan: Mapped[Optional["Scan"]] = relationship(back_populates="tool_executions")


class LLMSession(Base):
    """Conversation history for terminal REPL sessions."""

    __tablename__ = "llm_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    program: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    messages: Mapped[list] = mapped_column(JSON, default=list)
    tool_executions: Mapped[list] = mapped_column(JSON, default=list)
