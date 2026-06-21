"""SSRF and tool-call guard.

Validates URLs and tool invocation parameters *before* the agent executes them,
preventing the LLM from weaponizing the platform's network access.

Threat classes addressed:
  * SSRF via AI Agents — block requests to private/reserved IP ranges (RFC1918,
    loopback, link-local, cloud metadata endpoints like 169.254.169.254).
  * Tool Injection — reject tool-call arguments that contain command injection or
    path traversal payloads.
  * Function Calling Abuse — enforce an allowlist of permitted tool names so the
    model cannot invoke tools it was not explicitly granted access to.
  * Agent-to-Agent Attacks — validate inter-agent message envelopes to prevent
    one compromised agent from issuing unauthorized commands to another.

Implements :class:`src.security.guardrails.base.BaseGuardrail`.
Placeholder — implemented in Milestone M7.
"""

from __future__ import annotations

from typing import Any

from src.security.guardrails.base import BaseGuardrail, GuardrailResult


class SSRFGuard(BaseGuardrail):
    """Blocks SSRF and validates tool-call parameters before execution."""

    name = "ssrf_guard"

    async def check(self, context: dict[str, Any]) -> GuardrailResult:
        """Validate a tool invocation in ``context``.

        Expected context keys:
            tool_name (str): Name of the tool being called.
            tool_args (dict): Arguments the model supplied.
            allowed_tools (list[str]): Explicit allowlist for this user/role.
            url (str | None): URL argument if the tool makes an HTTP request.

        Returns:
            GuardrailResult — blocked if the tool, args, or URL violate policy.
        """
        raise NotImplementedError("Implemented in Milestone M7")
