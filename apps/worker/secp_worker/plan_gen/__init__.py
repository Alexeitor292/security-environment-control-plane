"""Worker-only B1B-PR5B real-plan-generation package (ADR-022).

It owns the plan-only process boundary, the plan-only command grammar, the worker-only plan-only
capability, the two-``SecretMaterial`` projection contract, and the durable plan-generation
orchestration. The dedicated plan-only seal is now ``_PLAN_ONLY_PROCESS_SEALED = False``, so the
production issuer can construct a real executor for a valid controlled-live context — but the
shipped ``PlanExecutionComposition`` is DISABLED, so the ordinary path STOPS at the composition gate
before
any executor is constructed, and both generic B1-A subprocess seals remain ``True`` (apply/destroy
stay impossible).
"""
