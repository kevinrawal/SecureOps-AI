"""Conditional edge functions for the SecureOps AI agent graph.

All routers are pure functions: (ThreatState) -> str. No IO, no side effects,
fully unit-testable without any mocks.

Edge destinations returned by each router must match node names registered
in build_graph() (or the special "end" sentinel mapped to END).
"""
from __future__ import annotations

from src.agents.grader import GRADE_PASS_THRESHOLD
from src.core.schema import ThreatState

MAX_REWRITES: int = 2


def route_after_injection(state: ThreatState) -> str:
    """Route after injection_check_node.

    Returns:
        "retrieve" if the check passed, "end" if the event was blocked.
    """
    if state.get("injection_blocked"):
        return "end"
    return "retrieve"


def route_after_grade(state: ThreatState) -> str:
    """Route after grade_node.

    Decision tree:
      - score >= GRADE_PASS_THRESHOLD -> proceed to remediation
      - score <  threshold AND rewrite_count < MAX_REWRITES -> rewrite (loop)
      - score <  threshold AND rewrite_count >= MAX_REWRITES -> remediation (best-effort)
    """
    score: float = state.get("retrieval_score", 0.0)
    rewrite_count: int = state.get("rewrite_count", 0)

    if score >= GRADE_PASS_THRESHOLD:
        return "remediation"
    if rewrite_count < MAX_REWRITES:
        return "rewrite"
    return "remediation"


def route_after_remediation(state: ThreatState) -> str:
    """Route after remediation_node.

    CRITICAL severity events require human approval before the report is
    generated. All other severities go directly to the reporter.
    """
    severity: str = (state.get("severity") or "").upper()
    if severity == "CRITICAL":
        return "human_review"
    return "reporter"


def route_after_human_review(state: ThreatState) -> str:
    """Route after human_review_node (post-interrupt resume).

    Approved -> reporter.  Rejected -> end (no report generated).
    """
    if state.get("human_approved"):
        return "reporter"
    return "end"
