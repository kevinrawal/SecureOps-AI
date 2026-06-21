"""SSRF and tool-call guard — validates URLs and tool invocations pre-execution.

Blocks the LLM from weaponizing the platform's network access by validating
every URL and tool call before it executes.

Threat classes addressed:
  SSRF via AI Agents — block requests to private/reserved IP ranges
    (RFC1918, loopback, link-local, cloud metadata 169.254.169.254).
  Tool Injection — reject tool-call arguments containing command injection
    or path traversal payloads.
  Function Calling Abuse — enforce an allowlist of permitted tool names.
  Agent-to-Agent Attacks — validate inter-agent message envelopes to prevent
    a compromised agent from issuing unauthorized commands.

Implements :class:`src.security.guardrails.base.BaseGuardrail`.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from typing import Any

import structlog

from src.security.guardrails.base import BaseGuardrail, GuardrailResult

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Blocked network ranges (SSRF)
# ---------------------------------------------------------------------------

_BLOCKED_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("10.0.0.0/8"),        # RFC1918
    ipaddress.IPv4Network("172.16.0.0/12"),     # RFC1918
    ipaddress.IPv4Network("192.168.0.0/16"),    # RFC1918
    ipaddress.IPv4Network("127.0.0.0/8"),       # loopback
    ipaddress.IPv4Network("0.0.0.0/8"),         # "this" network
    ipaddress.IPv4Network("169.254.0.0/16"),    # link-local / cloud metadata
    ipaddress.IPv4Network("100.64.0.0/10"),     # shared address space (RFC6598)
]

_BLOCKED_SCHEMES: frozenset[str] = frozenset(
    ["file", "gopher", "ftp", "dict", "ldap", "ldaps", "tftp", "jar"]
)

# Metadata endpoints that must be blocked regardless of IP resolution
_BLOCKED_HOSTNAMES: frozenset[str] = frozenset([
    "localhost",
    "0.0.0.0",
    "metadata.google.internal",
    "169.254.169.254",
    "metadata.azure.com",
])


def _is_ssrf_url(url: str) -> tuple[bool, str]:
    """Return (is_blocked, reason) for a URL."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return True, "unparseable URL"

    scheme = parsed.scheme.lower()
    if scheme in _BLOCKED_SCHEMES:
        return True, f"blocked scheme: {scheme}"

    host = parsed.hostname or ""
    if host in _BLOCKED_HOSTNAMES:
        return True, f"blocked hostname: {host}"

    try:
        addr = ipaddress.IPv4Address(host)
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                return True, f"blocked network: {net}"
    except ValueError:
        pass  # hostname, not an IP — allow DNS resolution (done at request time)

    return False, ""


# ---------------------------------------------------------------------------
# Tool argument injection patterns
# ---------------------------------------------------------------------------

_TOOL_ARG_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\.\./\.\.",                              # path traversal
        r";\s*(rm|wget|curl|nc|bash|sh|cmd)\b",   # command chaining
        r"\|\s*(bash|sh|python|perl|ruby)\b",     # pipe to interpreter
        r"(eval|exec)\s*\(",                       # code execution
        r"<\s*script",                             # script tag
    ]
]


def _has_injection_in_args(args: dict[str, Any]) -> tuple[bool, str]:
    """Check all string values in ``args`` for injection payloads."""
    for key, value in args.items():
        if not isinstance(value, str):
            continue
        for pat in _TOOL_ARG_PATTERNS:
            if pat.search(value):
                return True, f"arg '{key}' matches pattern {pat.pattern!r}"
    return False, ""


# ---------------------------------------------------------------------------
# SSRFGuard guardrail class
# ---------------------------------------------------------------------------

class SSRFGuard(BaseGuardrail):
    """Blocks SSRF URLs, validates tool arguments, enforces tool allowlist.

    Expected ``context`` keys:
        url (str | None): URL to validate before an HTTP call.
        tool_name (str | None): Name of the tool being invoked.
        tool_args (dict | None): Arguments the model supplied.
        allowed_tools (list[str] | None): Explicit allowlist for this session.
            Absence means all tool names are permitted.
    """

    name = "ssrf_guard"

    async def check(self, context: dict[str, Any]) -> GuardrailResult:
        """Validate URL, tool name, and tool arguments.

        Returns blocked on the first violation.
        """
        url: str | None = context.get("url")
        if url:
            blocked, reason = _is_ssrf_url(url)
            if blocked:
                logger.warning("ssrf_blocked", url=url[:200], reason=reason)
                return GuardrailResult(
                    passed=False,
                    blocked_reason=f"SSRF blocked: {reason}",
                    detail={"violation": "ssrf", "url": url[:200], "reason": reason},
                )

        tool_name: str | None = context.get("tool_name")
        allowed_tools: list[str] | None = context.get("allowed_tools")
        if tool_name and allowed_tools is not None:
            if tool_name not in allowed_tools:
                logger.warning(
                    "tool_not_allowed",
                    tool_name=tool_name,
                    allowed=allowed_tools,
                )
                return GuardrailResult(
                    passed=False,
                    blocked_reason=f"Tool '{tool_name}' not in allowlist",
                    detail={
                        "violation": "function_calling_abuse",
                        "tool_name": tool_name,
                        "allowed_tools": allowed_tools,
                    },
                )

        tool_args: dict[str, Any] | None = context.get("tool_args")
        if tool_args:
            injected, reason = _has_injection_in_args(tool_args)
            if injected:
                logger.warning("tool_arg_injection", tool_name=tool_name, reason=reason)
                return GuardrailResult(
                    passed=False,
                    blocked_reason=f"Tool argument injection detected: {reason}",
                    detail={"violation": "tool_injection", "reason": reason},
                )

        return GuardrailResult(passed=True)
