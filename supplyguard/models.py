"""SQLAlchemy database models for SupplyGuard scans, findings, and remediation attempts."""

import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)


class Base(DeclarativeBase):
    """Base declarative class for all SupplyGuard models."""


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


class Scan(Base):
    """Represents a completed or in-progress security scan session."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_path: Mapped[str] = mapped_column(String(512), nullable=False)
    started_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=_utcnow, nullable=False
    )
    finished_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    components_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
    remediations: Mapped[list["RemediationAttempt"]] = relationship(
        "RemediationAttempt", back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    """Represents an individual security finding discovered during a scan."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)  # sbom_osv, secrets, sast
    severity: Mapped[str] = mapped_column(String(32), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    file: Mapped[str] = mapped_column(String(512), nullable=False)
    line: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    cwe: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    raw_json: Mapped[str] = mapped_column(Text, default="", nullable=False)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    remediations: Mapped[list["RemediationAttempt"]] = relationship(
        "RemediationAttempt", back_populates="finding", cascade="all, delete-orphan"
    )


class RemediationAttempt(Base):
    """Represents an automated or manual remediation attempt and audit trail."""

    __tablename__ = "remediation_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), nullable=False)
    finding_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("findings.id"), nullable=True
    )
    strategy: Mapped[str] = mapped_column(String(64), nullable=False)  # DETERMINISTIC, LLM_ASSISTED, etc.
    iteration: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)  # RESOLVED, FIX_FAILED, SKIPPED
    diff_text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    explanation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=_utcnow, nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="remediations")
    finding: Mapped["Finding"] = relationship("Finding", back_populates="remediations")


def init_db(db_path: Path | str = "supplyguard.db") -> tuple[Any, sessionmaker]:
    """Initialize the SQLite database engine and create tables.

    Args:
        db_path: Target SQLite filepath.

    Returns:
        Tuple of (engine, sessionmaker factory).
    """
    db_uri = f"sqlite:///{db_path}"
    engine = create_engine(db_uri, echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    return engine, session_factory
