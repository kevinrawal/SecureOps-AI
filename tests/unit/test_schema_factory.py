"""Unit tests for core schema round-tripping and the model factory switching.

The factory test patches the environment and mocks the provider SDK so no real
model is constructed and no network/credentials are needed.
"""

from __future__ import annotations

import sys
import types

import pytest

from src.core.schema import (
    AuditEntry,
    EventSourceType,
    Role,
    SecureEvent,
    SeverityLevel,
)


# --- schema -----------------------------------------------------------------

def test_secure_event_json_round_trip():
    event = SecureEvent(
        source_type=EventSourceType.CLOUD,
        source_name="CloudTrail",
        severity=SeverityLevel.MEDIUM,
        title="Unusual AssumeRole",
        description="Role assumed from new geography.",
        indicators=["arn:aws:iam::123:role/admin"],
    )
    restored = SecureEvent.model_validate_json(event.model_dump_json())
    assert restored == event
    assert restored.event_id == event.event_id


def test_enums_cover_expected_members():
    assert {s.value for s in SeverityLevel} == {
        "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    }
    assert {r.value for r in Role} == {"ANALYST", "ENGINEER", "ADMIN"}
    assert EventSourceType("CVE") is EventSourceType.CVE


def test_audit_entry_defaults():
    entry = AuditEntry(event_id="e1", actor="grader", action="grade")
    assert entry.entry_id
    assert entry.timestamp.tzinfo is not None      # UTC-aware


# --- model factory ----------------------------------------------------------

def test_get_llm_groq_selects_fast_model_for_grading(monkeypatch):
    """get_llm('grading') must request the fast Groq model, default otherwise."""
    captured: dict[str, str] = {}

    fake_module = types.ModuleType("langchain_groq")

    class FakeChatGroq:
        def __init__(self, *, model, temperature, api_key):
            captured["model"] = model

    fake_module.ChatGroq = FakeChatGroq
    monkeypatch.setitem(sys.modules, "langchain_groq", fake_module)

    from src.core import models_factory
    from src.core.config import settings

    monkeypatch.setattr(settings, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(settings, "GROQ_MODEL", "llama-3.3-70b-versatile")
    monkeypatch.setattr(settings, "GROQ_MODEL_FAST", "llama-3.1-8b-instant")

    models_factory.get_llm("grading")
    assert captured["model"] == "llama-3.1-8b-instant"

    models_factory.get_llm("default")
    assert captured["model"] == "llama-3.3-70b-versatile"


def test_get_llm_unknown_provider_raises(monkeypatch):
    from src.core import models_factory
    from src.core.config import settings

    monkeypatch.setattr(settings, "LLM_PROVIDER", "does-not-exist")
    with pytest.raises(ValueError):
        models_factory.get_llm()
