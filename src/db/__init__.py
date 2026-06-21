"""Database engine and connection utilities.

Provides the shared SQLAlchemy async engine used by:
  - Alembic migration runner (alembic/env.py)
  - Audit log persistence (src/security/audit.py, M7)
  - Any future ORM/Core queries

The engine is a process-wide singleton backed by asyncpg.
"""

from src.db.engine import get_engine

__all__ = ["get_engine"]
