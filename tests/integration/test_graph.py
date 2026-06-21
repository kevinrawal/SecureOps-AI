"""Integration tests for the compiled LangGraph agent graph.

Placeholder — the graph is built in Milestones M5-M6. This will run a seeded
event end-to-end (inject_check -> retrieve -> grade -> [rewrite] -> remediation
-> human_review -> report) against test doubles for Pinecone and the LLM.
"""

import pytest

pytestmark = pytest.mark.skip(reason="Agent graph implemented in Milestones M5-M6")


def test_graph_end_to_end_placeholder():
    raise NotImplementedError
