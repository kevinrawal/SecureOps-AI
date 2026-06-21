"""PII masker guardrail — detects and redacts sensitive personal data.

Layer 1 (regex) covers common PII patterns. The guardrail mutates
``context["masked_text"]`` in place rather than blocking, so callers can use
the clean version downstream while still knowing what was found.

Threat classes addressed:
  Sensitive Information Disclosure — SSNs, emails, phones, card numbers,
    internal IP addresses, bearer tokens, API keys.
  Cross-User Context Leakage — prevents one tenant's PII from leaking into
    another user's LLM context or audit records.

Implements :class:`src.security.guardrails.base.BaseGuardrail`.
"""
from __future__ import annotations

import re
from typing import Any

import structlog

from src.security.guardrails.base import BaseGuardrail, GuardrailResult

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# PII pattern registry: (name, compiled pattern, replacement)
# ---------------------------------------------------------------------------

_PII_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "email",
        re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
        "[REDACTED:EMAIL]",
    ),
    (
        "phone_us",
        re.compile(r"\b(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b"),
        "[REDACTED:PHONE]",
    ),
    (
        "ssn",
        re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
        "[REDACTED:SSN]",
    ),
    (
        "credit_card",
        re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"),
        "[REDACTED:CARD]",
    ),
    (
        "ipv4_private",
        re.compile(
            r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        "[REDACTED:INTERNAL_IP]",
    ),
    (
        "bearer_token",
        re.compile(r"\bBearer\s+[a-zA-Z0-9\-._~+/]+=*", re.IGNORECASE),
        "Bearer [REDACTED:TOKEN]",
    ),
    (
        "api_key",
        re.compile(r"\b(api[_\-]?key|token|secret)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{16,}['\"]?", re.IGNORECASE),
        "[REDACTED:API_KEY]",
    ),
]


class PIIMasker(BaseGuardrail):
    """Masks PII in text; always passes (masking, not blocking).

    After ``check()``, read ``context["masked_text"]`` for the sanitized
    version and ``context["pii_detected"]`` for the list of pattern names hit.
    """

    name = "pii_masker"

    async def check(self, context: dict[str, Any]) -> GuardrailResult:
        """Scan and redact PII from ``context["text"]``.

        Mutates context in place:
            masked_text (str): Text with PII replaced by redaction tokens.
            pii_detected (list[str]): Pattern names that matched.

        Always returns a passing GuardrailResult — use ``masked_text`` downstream.
        """
        text: str = context.get("text", "")
        masked = text
        detected: list[str] = []

        for name, pattern, replacement in _PII_PATTERNS:
            new_text, count = pattern.subn(replacement, masked)
            if count:
                detected.append(name)
                masked = new_text

        context["masked_text"] = masked
        context["pii_detected"] = detected

        if detected:
            logger.info(
                "pii_masked",
                patterns=detected,
                original_length=len(text),
                masked_length=len(masked),
            )

        return GuardrailResult(
            passed=True,
            detail={"pii_detected": detected, "count": len(detected)},
        )
