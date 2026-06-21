"""create audit_entries table

Revision ID: 001
Revises:
Create Date: 2026-06-21 00:00:00.000000

The audit_entries table is the foundation of the immutable audit log.
Immutability is enforced at two levels:
  1. Application layer — operator.add in ThreatState means nodes can only append.
  2. Database layer — in production, grant INSERT + SELECT only to the app role;
     no UPDATE or DELETE. See the production hardening note in docs/M7-security/.
"""
from __future__ import annotations

from alembic import op

revision: str = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS audit_entries (
            entry_id    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            event_id    UUID,
            actor       VARCHAR(255) NOT NULL,
            action      VARCHAR(255) NOT NULL,
            detail      JSONB       NOT NULL DEFAULT '{}'
        )
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_event_id  ON audit_entries (event_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries (timestamp)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_entries")
