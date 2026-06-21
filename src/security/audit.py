"""Immutable audit log: AuditEntry persistence to PostgreSQL.

Each agent node action is appended to ThreatState.audit_trail (operator.add —
append-only inside the graph), then flushed to the audit_entries table at the
report node via the shared async engine (src.db.engine.get_engine).

Table schema is managed by Alembic migration 001_create_audit_entries.
Run `uv run alembic upgrade head` before first use.

Placeholder — implemented in Milestone M7. See docs/M7-security/ for design.
"""
