"""Dedicated staging-live worker package (SECP-B2-5-pre).

Production-grade but DELIBERATELY UNWIRED adapters + composition + canaries for the later, explicit,
out-of-Git-bootstrap staging activation. NORMAL worker/consumer/runtime/main code must NEVER import
this package (an architecture guard enforces it). Nothing here contacts OpenBao, Proxmox, a CA, a
network, or any target at import, construction, or test time.
"""
