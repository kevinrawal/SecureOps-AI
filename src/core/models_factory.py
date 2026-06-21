"""The single swappable model layer for SecureOps AI.

All LLM and embedding clients in the platform are constructed here and nowhere
else. Switching providers is therefore an environment-variable change
(``LLM_PROVIDER`` / ``EMBEDDING_PROVIDER``), and any *functional* change to how
models are called (retries, cost caps, callbacks) is made once in this file and
applies to every call site.

Provider SDKs are imported lazily inside each branch so unused providers need
not be installed — the base install runs on free Groq + local HuggingFace
embeddings only. See ``docs/models.md`` for the swap procedure and the extra
dependencies each provider requires.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from src.core.config import settings

if TYPE_CHECKING:  # avoid importing heavy/optional SDKs at module load
    from langchain_core.embeddings import Embeddings
    from langchain_core.language_models.chat_models import BaseChatModel

logger = structlog.get_logger(__name__)


def get_llm(task: str = "default") -> "BaseChatModel":
    """Return a chat model for the configured provider.

    Args:
        task: Intent hint. ``"grading"`` (and other cheap tasks) select a
            smaller/faster model where the provider offers one; anything else
            uses the default high-quality model.

    Returns:
        A LangChain ``BaseChatModel`` ready to invoke. ``temperature=0`` for
        deterministic security reasoning.

    Raises:
        ValueError: If ``settings.LLM_PROVIDER`` is unknown.
    """
    provider = settings.LLM_PROVIDER
    logger.debug("llm_factory", provider=provider, task=task)

    if provider == "groq":
        from langchain_groq import ChatGroq

        model = settings.GROQ_MODEL_FAST if task == "grading" else settings.GROQ_MODEL
        return ChatGroq(
            model=model,
            temperature=0,
            api_key=settings.GROQ_API_KEY,
        )

    if provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=settings.OPENAI_MODEL,
            temperature=0,
            api_key=settings.OPENAI_API_KEY,
        )

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=settings.ANTHROPIC_MODEL,
            temperature=0,
            api_key=settings.ANTHROPIC_API_KEY,
        )

    raise ValueError(f"Unknown LLM_PROVIDER: {provider!r}")


def get_embeddings() -> "Embeddings":
    """Return an embeddings client for the configured provider.

    Default is local HuggingFace ``all-MiniLM-L6-v2`` (384-dim, CPU, no API
    cost). The embedding dimension is config-driven (``EMBEDDING_DIMENSION``)
    and must match the Pinecone index dimension (see ``src/rag``).

    Raises:
        ValueError: If ``settings.EMBEDDING_PROVIDER`` is unknown.
    """
    provider = settings.EMBEDDING_PROVIDER
    logger.debug("embedding_factory", provider=provider, model=settings.EMBEDDING_MODEL)

    if provider == "huggingface":
        from langchain_huggingface import HuggingFaceEmbeddings

        return HuggingFaceEmbeddings(model_name=settings.EMBEDDING_MODEL)

    if provider == "openai":
        from langchain_openai import OpenAIEmbeddings

        return OpenAIEmbeddings(
            model=settings.EMBEDDING_MODEL,
            api_key=settings.OPENAI_API_KEY,
        )

    raise ValueError(f"Unknown EMBEDDING_PROVIDER: {provider!r}")
