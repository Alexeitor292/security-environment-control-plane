"""Domain services — the only place control-plane state is mutated.

Services enforce authorization, lifecycle rules, the approval gate, and audit.
Routers are thin adapters over these functions; tests call them directly.
"""
