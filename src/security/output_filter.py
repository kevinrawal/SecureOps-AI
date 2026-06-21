"""Output filter guardrail.

Sanitizes LLM-generated text *after* it is produced and *before* it is stored
or returned to a caller. Targets three threat classes:

  * Unsafe Output Generation — detect and redact attacker-influenced content in
    model responses (e.g. injected instructions that survived the input check).
  * System Prompt Leakage — detect if the model echoed its system prompt in the
    response (regex + LLM judge Layer 2).
  * Hallucination Exploitation — flag responses that make factual-sounding claims
    unsupported by the retrieved runbooks (grounding score comparison).

Implements :class:`src.security.guardrails.base.BaseGuardrail`.
Placeholder — implemented in Milestone M7.
"""

from __future__ import annotations

from typing import Any

from src.security.guardrails.base import BaseGuardrail, GuardrailResult


class OutputFilter(BaseGuardrail):
    """Post-LLM output sanitization guardrail.

    Checks the model's response for leaked system-prompt content, injected
    instructions, and claims that diverge significantly from retrieved grounding.
    """

    name = "output_filter"

    async def check(self, context: dict[str, Any]) -> GuardrailResult:
        """Check LLM output in ``context["llm_output"]`` against grounding docs.

        Expected context keys:
            llm_output (str): The raw model response.
            retrieved_docs (list[dict]): Runbooks used for grounding.
            system_prompt_hash (str): Hash of the system prompt for leakage check.

        Returns:
            GuardrailResult — blocked if leakage or unsafe content detected.
        """
        raise NotImplementedError("Implemented in Milestone M7")
