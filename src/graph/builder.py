"""LangGraph StateGraph construction and compilation for SecureOps AI.

Public API: build_graph(checkpointer=None) -> CompiledStateGraph

Checkpointer:
  interrupt() in human_review_node requires a BaseCheckpointSaver to be
  attached. build_graph() defaults to MemorySaver (in-process, zero deps).
  Production (M9+) passes AsyncPostgresSaver:
      from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
      build_graph(checkpointer=AsyncPostgresSaver.from_conn_string(...))
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from src.agents.grader import grade_node
from src.agents.human_review import human_review_node
from src.agents.injection_check import injection_check_node
from src.agents.remediation import remediation_node
from src.agents.reporter import reporter_node
from src.agents.retrieval import retrieve_node
from src.agents.rewriter import rewrite_node
from src.core.schema import ThreatState
from src.graph.routers import (
    route_after_grade,
    route_after_human_review,
    route_after_injection,
    route_after_remediation,
)

if TYPE_CHECKING:
    from langgraph.checkpoint.base import BaseCheckpointSaver
    from langgraph.graph.graph import CompiledGraph


def build_graph(
    checkpointer: Optional["BaseCheckpointSaver"] = None,
) -> "CompiledGraph":
    """Build and compile the full SecureOps AI agent graph.

    Graph topology:
        injection_check
            |-- blocked --> END
            |-- pass   --> retrieve
        retrieve --> grade
        grade
            |-- score >= 0.7 OR rewrites exhausted --> remediation
            |-- score < 0.7 AND rewrites left      --> rewrite --> retrieve
        remediation
            |-- CRITICAL --> human_review (interrupt) --> reporter | END
            |-- other    --> reporter
        reporter --> END

    Args:
        checkpointer: Checkpoint backend for HITL interrupt/resume support.
            Defaults to MemorySaver (in-process). Pass AsyncPostgresSaver for
            production persistence.

    Returns:
        A compiled LangGraph StateGraph ready for ainvoke().
    """
    graph = StateGraph(ThreatState)

    # ── Register nodes ──────────────────────────────────────────────────
    graph.add_node("injection_check", injection_check_node)
    graph.add_node("retrieve", retrieve_node)
    graph.add_node("grade", grade_node)
    graph.add_node("rewrite", rewrite_node)
    graph.add_node("remediation", remediation_node)
    graph.add_node("human_review", human_review_node)
    graph.add_node("reporter", reporter_node)

    # ── Entry point ──────────────────────────────────────────────────────
    graph.set_entry_point("injection_check")

    # ── Edges ────────────────────────────────────────────────────────────
    graph.add_conditional_edges(
        "injection_check",
        route_after_injection,
        {"retrieve": "retrieve", "end": END},
    )
    graph.add_edge("retrieve", "grade")
    graph.add_conditional_edges(
        "grade",
        route_after_grade,
        {"rewrite": "rewrite", "remediation": "remediation"},
    )
    graph.add_edge("rewrite", "retrieve")          # HyDE loop
    graph.add_conditional_edges(
        "remediation",
        route_after_remediation,
        {"human_review": "human_review", "reporter": "reporter"},
    )
    graph.add_conditional_edges(
        "human_review",
        route_after_human_review,
        {"reporter": "reporter", "end": END},
    )
    graph.add_edge("reporter", END)

    return graph.compile(checkpointer=checkpointer or MemorySaver())
