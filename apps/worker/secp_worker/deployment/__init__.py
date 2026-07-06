"""Worker-only real staging-lab deployment engine (SECP-B4).

DELIBERATELY UNWIRED and sealed by default. Normal API/UI/worker runtime never constructs a live
deployment executor. Real host action is impossible until: (1) this PR is merged, (2) a
deployment-local bootstrap bundle is mounted into the worker, and (3) an exact app-generated plan is
explicitly approved. Nothing here is contacted during implementation — every I/O primitive (SSH,
Proxmox HTTPS, OpenBao) is an injected seam whose shipped default refuses, and tests drive fakes.
"""
