"""Output filter guardrail — post-LLM sanitization.

Scans model-generated text AFTER it is produced and BEFORE it is stored or
returned to a caller. Three threat classes:

  Unsafe Output Generation — detect injected instructions that survived the
    input check and are now echoed in the LLM response.
  System Prompt Leakage — detect if the model reflected its system prompt
    content in the response (regex heuristics).
  Hallucination Exploitation — flag responses that make factual-sounding
    claims unsupported by the retrieved runbooks (grounding score gate).

Implements :class:`src.security.guardrails.base.BaseGuardrail`.
"""
from __future__ import annotations

import re
from typing import Any

import structlog

from src.security.guardrails.base import BaseGuardrail, GuardrailResult
from src.security.injection import detect_l1

logger = structlog.get_logger(__name__)

# Phrases that indicate the model echoed its system prompt.
_SYSTEM_PROMPT_LEAKAGE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"you\s+are\s+a\s+(senior\s+)?security\s+(incident\s+responder|runbook\s+relevance\s+judge)",
        r"rules?\s*:\s*\n\s*1\.",          # echoed numbered rules
        r"respond\s+only\s+with\s+valid\s+json",
        r"scoring\s+guide\s*:",
        r"base\s+every\s+step\s+on\s+the\s+provided\s+runbooks",
        r"do\s+not\s+explain\s+what\s+you\s+are\s+doing",
    ]
]

# Grounding score below this threshold triggers a hallucination warning.
_HALLUCINATION_SCORE_THRESHOLD: float = 0.3


class OutputFilter(BaseGuardrail):
    """Post-LLM output sanitization guardrail.

    Expected ``context`` keys:
        llm_output (str): The raw model response to inspect.
        retrieval_score (float): Grading score from the grader node (0.0-1.0).
            Absence is treated as 0.0 (conservative).
        check_leakage (bool): If True, run system-prompt leakage check.
            Default True.
        check_injection (bool): If True, run injection echo detection.
            Default True.
    """

    name = "output_filter"

    async def check(self, context: dict[str, Any]) -> GuardrailResult:
        """Scan LLM output for leakage, injected content, and hallucination.

        Returns blocked result on the first violation found.
        """
        output: str = context.get("llm_output", "")

        if context.get("check_injection", True):
            category, pattern = detect_l1(output)
            if category:
                logger.warning(
                    "output_filter_injection_echo",
                    category=category,
                    pattern=pattern,
                )
                return GuardrailResult(
                    passed=False,
                    blocked_reason=f"LLM output contains injection echo [{category}]",
                    detail={"violation": "injection_echo", "category": category},
                )

        if context.get("check_leakage", True):
            for pat in _SYSTEM_PROMPT_LEAKAGE_PATTERNS:
                if pat.search(output):
                    logger.warning(
                        "output_filter_prompt_leakage",
                        pattern=pat.pattern,
                    )
                    return GuardrailResult(
                        passed=False,
                        blocked_reason="System prompt content detected in LLM output",
                        detail={"violation": "system_prompt_leakage", "pattern": pat.pattern},
                    )

        score: float = float(context.get("retrieval_score", 0.0))
        if score < _HALLUCINATION_SCORE_THRESHOLD:
            logger.warning(
                "output_filter_low_grounding",
                retrieval_score=score,
                threshold=_HALLUCINATION_SCORE_THRESHOLD,
            )
            return GuardrailResult(
                passed=False,
                blocked_reason=(
                    f"LLM output grounding score {score:.2f} below "
                    f"threshold {_HALLUCINATION_SCORE_THRESHOLD}"
                ),
                detail={
                    "violation": "hallucination_risk",
                    "retrieval_score": score,
                    "threshold": _HALLUCINATION_SCORE_THRESHOLD,
                },
            )

        return GuardrailResult(passed=True)
