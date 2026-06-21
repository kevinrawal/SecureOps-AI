"""Unit tests for the retrieval grader and routing logic."""
from __future__ import annotations

import pytest

from src.agents.grader import GRADE_PASS_THRESHOLD, _parse_grade_response
from src.graph.routers import MAX_REWRITES, route_after_grade, route_after_injection


# ---------------------------------------------------------------------------
# _parse_grade_response
# ---------------------------------------------------------------------------

def test_parse_grade_valid_json():
    score, reasoning = _parse_grade_response('{"score": 0.85, "reasoning": "Good match"}')
    assert score == pytest.approx(0.85)
    assert "Good match" in reasoning


def test_parse_grade_json_clamps_above_1():
    score, _ = _parse_grade_response('{"score": 1.5, "reasoning": "too high"}')
    assert score == pytest.approx(1.0)


def test_parse_grade_json_clamps_below_0():
    score, _ = _parse_grade_response('{"score": -0.3, "reasoning": "negative"}')
    assert score == pytest.approx(0.0)


def test_parse_grade_fallback_extracts_float():
    # Malformed JSON but contains a valid float
    score, reasoning = _parse_grade_response("The relevance score is 0.6 out of 1.0.")
    assert score == pytest.approx(0.6)
    assert "extracted" in reasoning


def test_parse_grade_fallback_returns_zero_on_failure():
    score, reasoning = _parse_grade_response("No useful information here at all.")
    assert score == pytest.approx(0.0)
    assert "failed" in reasoning


# ---------------------------------------------------------------------------
# route_after_grade
# ---------------------------------------------------------------------------

def test_route_after_grade_pass():
    state = {"retrieval_score": GRADE_PASS_THRESHOLD, "rewrite_count": 0}
    assert route_after_grade(state) == "remediation"


def test_route_after_grade_high_score_skips_rewrite():
    state = {"retrieval_score": 0.95, "rewrite_count": 0}
    assert route_after_grade(state) == "remediation"


def test_route_after_grade_low_score_triggers_rewrite():
    state = {"retrieval_score": 0.3, "rewrite_count": 0}
    assert route_after_grade(state) == "rewrite"


def test_route_after_grade_loop_guard_exhausted():
    state = {"retrieval_score": 0.2, "rewrite_count": MAX_REWRITES}
    assert route_after_grade(state) == "remediation"


def test_route_after_grade_one_rewrite_remaining():
    state = {"retrieval_score": 0.2, "rewrite_count": MAX_REWRITES - 1}
    assert route_after_grade(state) == "rewrite"


# ---------------------------------------------------------------------------
# route_after_injection
# ---------------------------------------------------------------------------

def test_route_after_injection_passes():
    state = {"injection_blocked": False, "sanitized_description": "some event"}
    assert route_after_injection(state) == "retrieve"


def test_route_after_injection_blocks():
    state = {"injection_blocked": True}
    assert route_after_injection(state) == "end"


def test_route_after_injection_missing_key_defaults_to_retrieve():
    assert route_after_injection({}) == "retrieve"
