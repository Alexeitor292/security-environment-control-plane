"""The pending SDN family vocabulary. ONE declaration, imported by everything that needs it.

This existed in three places: the worker's ``SDN_PENDING_FAMILIES``, the control plane's
``PENDING_FAMILIES``, and a bare literal inside ``_pending_sdn_completeness`` — which was the copy
that actually decided whether visibility was complete. Two of the three were pinned to each other
by a test; the third was not pinned to anything.

The plane boundary forbids the control plane importing worker internals, so the worker copy remains
and is pinned to this one by test. Inside the control plane there is now exactly one.
"""

from __future__ import annotations

#: Families that must ALL be enumerated before any pending claim is made. There is no read-only
#: "does anything pend" endpoint, so completeness across every family is the only way to know, and a
#: partial enumeration is an unknown rather than a smaller answer.
PENDING_FAMILIES: tuple[str, ...] = ("zones", "vnets", "subnets", "controllers")

#: Version-dependent: present from PVE 9.0. A 404 on it is an ANSWER about the target rather than a
#: gap, but it must still have been ATTEMPTED — ``PUT /cluster/sdn`` commits pending fabrics too, so
#: a family nobody asked about makes the pending set knowably smaller than what would activate.
FABRICS_FAMILY = "fabrics"

#: Every family the pending state may carry.
ALL_PENDING_FAMILIES: tuple[str, ...] = (*PENDING_FAMILIES, FABRICS_FAMILY)
