"""PII masker guardrail.

Detects and redacts personally-identifiable information (PII) in event
descriptions and LLM outputs before data is stored in audit logs, returned via
the API, or passed between agents.

Threat classes addressed:
  * Sensitive Information Disclosure — prevent SSNs, emails, phone numbers,
    credentials from leaking into Pinecone vectors, audit records, or API responses.
  * Cross-User Context Leakage — ensure one tenant's PII cannot bleed into another
    user's LLM context (pairs with the context-isolation layer in RBAC).

Strategy (M7 implementation):
  Layer 1 — regex-based fast-path for common PII patterns (email, phone, card,
            SSN, IPv4 that look like internal addresses, bearer tokens).
  Layer 2 — optional LLM-based NER for residual PII that evades regex.

Implements :class:`src.security.guardrails.base.BaseGuardrail`.
Placeholder — implemented in Milestone M7.
"""

from __future__ import annotations

from typing import Any

from src.security.guardrails.base import BaseGuardrail, GuardrailResult


class PIIMasker(BaseGuardrail):
    """Detects and masks PII; does not block but mutates context in place.

    Unlike blocking guardrails, PIIMasker replaces detected PII with ``[REDACTED]``
    tokens and annotates the result, rather than returning a hard block.
    """

    name = "pii_masker"

    async def check(self, context: dict[str, Any]) -> GuardrailResult:
        """Scan and redact PII from ``context["text"]``.

        Expected context keys:
            text (str): Text to scan (event description or LLM output).

        Side-effects:
            Sets ``context["masked_text"]`` with redacted version.
            Sets ``context["pii_detected"]`` with list of pattern names found.

        Returns:
            GuardrailResult — always passes (masking, not blocking); caller reads
            ``context["masked_text"]`` for the clean version.
        """
        raise NotImplementedError("Implemented in Milestone M7")
