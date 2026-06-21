"""Unit tests for the retrieval grader (LLM-as-judge).

Placeholder — the grader is implemented in Milestone M5. Tests there mock the
LLM and assert score normalization (0.0-1.0) and the pass/fail threshold that
drives the rewrite loop. Kept as a skipped stub for module presence.
"""

import pytest

pytestmark = pytest.mark.skip(reason="Grader implemented in Milestone M5")


def test_grader_score_normalization_placeholder():
    raise NotImplementedError
