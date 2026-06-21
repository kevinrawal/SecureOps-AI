"""GuardrailPipeline — ordered chain of :class:`BaseGuardrail` checks.

Mirrors the ``ADAPTER_REGISTRY`` pattern in ingestion: callers run a pipeline
rather than calling guardrails individually, so the order is controlled in one
place and new checks slot in without touching call sites.

Typical pipeline order (defined in M7 during wiring):
  1. InjectionCheck  (input sanitization — always first, blocks LLM access)
  2. SSRFGuard       (before any tool/URL execution)
  3. PIIMasker       (before any data is stored or returned)
  4. OutputFilter    (after LLM response, before returning to caller)

Placeholder — implemented in Milestone M7.
"""

from __future__ import annotations

from typing import Any

import structlog

from src.security.guardrails.base import BaseGuardrail, GuardrailResult

logger = structlog.get_logger(__name__)


class GuardrailPipeline:
    """Runs an ordered list of guardrails, stopping on the first block.

    Usage (M7)::

        pipeline = GuardrailPipeline([InjectionCheck(), SSRFGuard()])
        result = await pipeline.run({"text": event.description, "user_id": uid})
        if not result.passed:
            raise SecurityError(result.blocked_reason)
    """

    def __init__(self, guardrails: list[BaseGuardrail]) -> None:
        """Initialise the pipeline with an ordered list of guardrails."""
        self._guardrails = guardrails

    async def run(self, context: dict[str, Any]) -> GuardrailResult:
        """Run each guardrail in order; return the first block or a final pass."""
        for guardrail in self._guardrails:
            result = await guardrail.check(context)
            logger.debug(
                "guardrail_checked",
                name=guardrail.name,
                passed=result.passed,
                reason=result.blocked_reason or None,
            )
            if not result.passed:
                logger.warning(
                    "guardrail_blocked",
                    name=guardrail.name,
                    reason=result.blocked_reason,
                )
                return result
        return GuardrailResult(passed=True)
