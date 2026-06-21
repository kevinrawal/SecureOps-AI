"""Langfuse v4 LangChain callback handler factory."""
from __future__ import annotations

from typing import Optional

import structlog
from langfuse.langchain import CallbackHandler  # pylint: disable=no-name-in-module

from src.core.config import settings

logger = structlog.get_logger(__name__)


def get_langfuse_handler() -> Optional[CallbackHandler]:
    """Return a fresh Langfuse LangChain callback handler for a single LLM call.

    Returns ``None`` when Langfuse is not configured (missing keys) so that
    agent nodes work without a running Langfuse instance — no tracing overhead
    in unconfigured environments or unit tests.

    A new instance is created on every call because LangChain callback handlers
    are single-use per invocation and must not be shared across concurrent calls.

    Usage in an agent node::

        handler = get_langfuse_handler()
        callbacks = [handler] if handler else []
        response = await llm.ainvoke(messages, config={"callbacks": callbacks})

    Returns:
        A configured ``CallbackHandler`` or ``None`` if keys are absent.
    """
    if not (settings.LANGFUSE_SECRET_KEY and settings.LANGFUSE_PUBLIC_KEY):
        return None

    return CallbackHandler(
        secret_key=settings.LANGFUSE_SECRET_KEY,
        public_key=settings.LANGFUSE_PUBLIC_KEY,
        host=settings.LANGFUSE_HOST,
    )
