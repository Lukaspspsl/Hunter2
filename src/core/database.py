"""Database operations for Hunter 2.

Extends Hunter 1.0 ops with Program / ToolExecution / LLMSession helpers
and scope-aware Subdomain insertion.
"""

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Generator, Iterable, Optional

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from .logger import get_logger
from .models import (
    Base,
    Directory,
    LLMSession,
    Port,
    Program,
    Scan,
    Screenshot,
    Secret,
    Subdomain,
    Technology,
    ToolExecution,
    Vulnerability,
)

log = get_logger("database")

_db: Optional["Database"] = None


class Database:
    def __init__(self, db_path: str = "./data/hunter2.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            echo=False,
            future=True,
        )
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)
        log.debug(f"Database initialized at {self.db_path}")

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ---------- Program ----------
    def upsert_program(
        self,
        name: str,
        platform: Optional[str] = None,
        aggressiveness: str = "passive",
    ) -> Program:
        with self.session() as s:
            prog = s.scalar(select(Program).where(Program.name == name))
            if prog is None:
                prog = Program(
                    name=name, platform=platform, aggressiveness=aggressiveness
                )
                s.add(prog)
            else:
                prog.platform = platform or prog.platform
                prog.aggressiveness = aggressiveness
            s.flush()
            return prog

    def get_program(self, name: str) -> Optional[Program]:
        with self.session() as s:
            return s.scalar(select(Program).where(Program.name == name))

    def list_programs(self) -> list[Program]:
        with self.session() as s:
            return list(s.scalars(select(Program).order_by(Program.name)))

    # ---------- Scan ----------
    def create_scan(
        self,
        target_source: str,
        program: Optional[str] = None,
        program_id: Optional[int] = None,
        aggressiveness: str = "passive",
        triggered_by: str = "manual",
        log_file: Optional[str] = None,
    ) -> int:
        with self.session() as s:
            scan = Scan(
                target_source=target_source,
                log_file=log_file,
                status="running",
                project=program or "default",
                program_id=program_id,
                aggressiveness=aggressiveness,
                triggered_by=triggered_by,
            )
            s.add(scan)
            s.flush()
            log.info(f"Created scan #{scan.id} program={program} level={aggressiveness}")
            return scan.id

    def complete_scan(self, scan_id: int, status: str = "completed") -> None:
        with self.session() as s:
            scan = s.get(Scan, scan_id)
            if scan:
                scan.completed_at = datetime.utcnow()
                scan.status = status

    def get_scan(self, scan_id: int) -> Optional[Scan]:
        with self.session() as s:
            return s.get(Scan, scan_id)

    def get_latest_scan(self, program: Optional[str] = None) -> Optional[Scan]:
        with self.session() as s:
            stmt = select(Scan).where(Scan.status == "completed")
            if program:
                stmt = stmt.where(Scan.project == program)
            stmt = stmt.order_by(Scan.completed_at.desc()).limit(1)
            return s.scalar(stmt)

    # ---------- Subdomain ----------
    def add_subdomains_bulk(
        self,
        scan_id: int,
        entries: Iterable[dict],
        previous_domains: Optional[set[str]] = None,
        program_id: Optional[int] = None,
    ) -> int:
        """entries: dicts with keys domain, source_tool, in_scope, oos_reason."""
        previous_domains = previous_domains or set()
        count = 0
        with self.session() as s:
            for e in entries:
                sub = Subdomain(
                    scan_id=scan_id,
                    program_id=program_id,
                    domain=e["domain"],
                    source_tool=e.get("source_tool"),
                    is_new=e["domain"] not in previous_domains,
                    in_scope=e.get("in_scope", True),
                    oos_reason=e.get("oos_reason"),
                )
                s.add(sub)
                count += 1
            s.flush()
        log.debug(f"Inserted {count} subdomains for scan #{scan_id}")
        return count

    def get_subdomains(
        self,
        scan_id: int,
        new_only: bool = False,
        in_scope_only: bool = True,
    ) -> list[Subdomain]:
        with self.session() as s:
            stmt = select(Subdomain).where(Subdomain.scan_id == scan_id)
            if new_only:
                stmt = stmt.where(Subdomain.is_new.is_(True))
            if in_scope_only:
                stmt = stmt.where(Subdomain.in_scope.is_(True))
            return list(s.scalars(stmt))

    def get_oos_subdomains(self, program: str) -> list[Subdomain]:
        with self.session() as s:
            stmt = (
                select(Subdomain)
                .join(Scan)
                .where(Scan.project == program)
                .where(Subdomain.in_scope.is_(False))
                .order_by(Subdomain.last_seen.desc())
            )
            return list(s.scalars(stmt))

    def get_all_domains_from_scan(self, scan_id: int) -> set[str]:
        with self.session() as s:
            stmt = select(Subdomain.domain).where(Subdomain.scan_id == scan_id)
            return set(s.scalars(stmt))

    # ---------- Port / Vuln / Tech / Screenshot / Directory ----------
    def add_port(self, subdomain_id: int, **kwargs) -> Port:
        with self.session() as s:
            p = Port(subdomain_id=subdomain_id, **kwargs)
            s.add(p)
            s.flush()
            return p

    def add_ports_bulk(self, subdomain_id: int, ports: list[dict]) -> int:
        with self.session() as s:
            for pd in ports:
                s.add(Port(subdomain_id=subdomain_id, **pd))
            s.flush()
        return len(ports)

    def add_vulnerability(self, subdomain_id: int, **kwargs) -> Vulnerability:
        with self.session() as s:
            v = Vulnerability(subdomain_id=subdomain_id, **kwargs)
            s.add(v)
            s.flush()
            return v

    def add_technology(self, subdomain_id: int, **kwargs) -> Technology:
        with self.session() as s:
            t = Technology(subdomain_id=subdomain_id, **kwargs)
            s.add(t)
            s.flush()
            return t

    def add_secret(self, scan_id: int, **kwargs) -> Secret:
        with self.session() as s:
            sec = Secret(scan_id=scan_id, **kwargs)
            s.add(sec)
            s.flush()
            return sec

    def add_screenshot(self, subdomain_id: int, **kwargs) -> Screenshot:
        with self.session() as s:
            sh = Screenshot(subdomain_id=subdomain_id, **kwargs)
            s.add(sh)
            s.flush()
            return sh

    def add_directory(self, subdomain_id: int, **kwargs) -> Directory:
        with self.session() as s:
            d = Directory(subdomain_id=subdomain_id, **kwargs)
            s.add(d)
            s.flush()
            return d

    # ---------- ToolExecution ----------
    def create_tool_execution(
        self,
        tool_name: str,
        scan_id: Optional[int] = None,
        program: Optional[str] = None,
        target: Optional[str] = None,
        args: Optional[dict] = None,
        triggered_by: str = "manual",
        llm_reasoning: Optional[str] = None,
    ) -> int:
        with self.session() as s:
            te = ToolExecution(
                tool_name=tool_name,
                scan_id=scan_id,
                program=program,
                target=target,
                args=args,
                triggered_by=triggered_by,
                llm_reasoning=llm_reasoning,
                status="running",
            )
            s.add(te)
            s.flush()
            return te.id

    def finish_tool_execution(
        self,
        execution_id: int,
        status: str,
        exit_code: Optional[int] = None,
        result_summary: Optional[str] = None,
        raw_output_path: Optional[str] = None,
    ) -> None:
        with self.session() as s:
            te = s.get(ToolExecution, execution_id)
            if te is None:
                return
            now = datetime.utcnow()
            te.completed_at = now
            te.status = status
            te.exit_code = exit_code
            te.result_summary = result_summary
            te.raw_output_path = raw_output_path
            if te.started_at:
                te.duration_ms = int(
                    (now - te.started_at).total_seconds() * 1000
                )

    def record_blocked_execution(
        self,
        tool_name: str,
        target: str,
        program: Optional[str],
        reason: str,
        triggered_by: str = "manual",
    ) -> int:
        with self.session() as s:
            te = ToolExecution(
                tool_name=tool_name,
                program=program,
                target=target,
                triggered_by=triggered_by,
                status="blocked_oos",
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                result_summary=f"BLOCKED: {reason}",
            )
            s.add(te)
            s.flush()
            return te.id

    def list_tool_executions(
        self,
        program: Optional[str] = None,
        limit: int = 200,
    ) -> list[ToolExecution]:
        with self.session() as s:
            stmt = select(ToolExecution)
            if program:
                stmt = stmt.where(ToolExecution.program == program)
            stmt = stmt.order_by(ToolExecution.started_at.desc()).limit(limit)
            return list(s.scalars(stmt))

    # ---------- LLMSession ----------
    def create_llm_session(self, program: Optional[str] = None) -> int:
        with self.session() as s:
            sess = LLMSession(program=program, messages=[], tool_executions=[])
            s.add(sess)
            s.flush()
            return sess.id

    def append_llm_message(self, session_id: int, role: str, content: str) -> None:
        with self.session() as s:
            sess = s.get(LLMSession, session_id)
            if sess is None:
                return
            msgs = list(sess.messages or [])
            msgs.append(
                {
                    "role": role,
                    "content": content,
                    "ts": datetime.utcnow().isoformat(),
                }
            )
            sess.messages = msgs

    def append_llm_tool_execution(self, session_id: int, execution_id: int) -> None:
        with self.session() as s:
            sess = s.get(LLMSession, session_id)
            if sess is None:
                return
            ids = list(sess.tool_executions or [])
            ids.append(execution_id)
            sess.tool_executions = ids

    def close_llm_session(self, session_id: int) -> None:
        with self.session() as s:
            sess = s.get(LLMSession, session_id)
            if sess:
                sess.ended_at = datetime.utcnow()

    # ---------- Stats ----------
    def get_scan_stats(self, scan_id: int) -> dict:
        with self.session() as s:
            sub_total = s.scalar(
                select(func.count(Subdomain.id)).where(Subdomain.scan_id == scan_id)
            )
            sub_new = s.scalar(
                select(func.count(Subdomain.id))
                .where(Subdomain.scan_id == scan_id)
                .where(Subdomain.is_new.is_(True))
            )
            sub_oos = s.scalar(
                select(func.count(Subdomain.id))
                .where(Subdomain.scan_id == scan_id)
                .where(Subdomain.in_scope.is_(False))
            )
            ports = s.scalar(
                select(func.count(Port.id))
                .join(Subdomain)
                .where(Subdomain.scan_id == scan_id)
            )
            vulns = s.scalar(
                select(func.count(Vulnerability.id))
                .join(Subdomain)
                .where(Subdomain.scan_id == scan_id)
            )
            secrets = s.scalar(
                select(func.count(Secret.id)).where(Secret.scan_id == scan_id)
            )
            return {
                "subdomains_total": sub_total or 0,
                "subdomains_new": sub_new or 0,
                "subdomains_oos": sub_oos or 0,
                "ports": ports or 0,
                "vulnerabilities": vulns or 0,
                "secrets": secrets or 0,
            }


def init_db(db_path: str = "./data/hunter2.db") -> Database:
    global _db
    _db = Database(db_path)
    return _db


def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db
