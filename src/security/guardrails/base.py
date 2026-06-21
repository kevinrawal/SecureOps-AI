"""Base guardrail interface — the composable security check contract.

Mirrors :class:`src.ingestion.adapters.base.BaseAdapter` in intent: each
security concern is an independent, testable class that the pipeline calls in
order. Adding a new check means subclassing :class:`BaseGuardrail` and adding it
to the pipeline — no existing code changes.

Threat classes each guardrail implementation maps to:
  Injection-check  → indirect prompt injection, jailbreak, system-prompt leakage
  OutputFilter     → unsafe output, hallucination exploitation, system-prompt leakage in response
  PIIMasker        → sensitive information disclosure, cross-user context leakage
  SSRFGuard        → SSRF via AI agents, tool injection, function-calling abuse

Placeholder — implemented in Milestone M7.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class GuardrailResult:
    """Outcome of one guardrail check.

    Attributes:
        passed: True if the check passed and processing should continue.
        blocked_reason: Human-readable reason when ``passed`` is False.
        detail: Arbitrary extra context (matched patterns, risk score, …).
    """

    passed: bool
    blocked_reason: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


class BaseGuardrail(ABC):
    """Abstract base for security guardrails.

    Each subclass implements :meth:`check` for one threat class. Guardrails are
    stateless by convention — all context needed for a check is passed in as
    ``context``.
    """

    #: Short name used in audit logs and metrics (set by each subclass).
    name: str = "base"

    @abstractmethod
    async def check(self, context: dict[str, Any]) -> GuardrailResult:
        """Run the guardrail check against ``context``.

        Args:
            context: Arbitrary key-value context the guardrail inspects (e.g.
                ``{"text": ..., "user_id": ..., "role": ...}``).

        Returns:
            :class:`GuardrailResult` indicating pass or block.
        """
