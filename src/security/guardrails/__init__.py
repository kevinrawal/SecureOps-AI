"""SecureOps AI security guardrails sub-package.

Guardrails are composable, ordered security checks that run at defined points in
the agent pipeline. Each implements :class:`BaseGuardrail`; the
:class:`GuardrailPipeline` chains them in order, stopping on the first block.

The pattern mirrors the ingestion adapter registry: adding a new check means
writing one class and registering it — no pipeline code changes.

Implemented in Milestone M7.
"""
