"""Worker-only B1B-PR5A real-plan-generation package (ADR-022).

It owns the SEALED plan-only process boundary, the plan-only command grammar, the worker-only
plan-only capability, the two-``SecretMaterial`` projection contract, and the durable
plan-generation
orchestration that STOPS at the seal. In PR5A nothing here constructs a process executor or runs a
process: the plan-only seal (``_PLAN_ONLY_PROCESS_SEALED = True``) refuses construction, exactly as
B1-A refuses all subprocess execution today.
"""
