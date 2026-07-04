"""Worker-only secret-backend adapters (SECP-B2-4).

Implementation details behind the ``WorkerSecretResolver`` seam. They are never imported by the
API or frontend, are never wired into shipped runtime (the shipped default remains the sealed
resolver), and construct no backend client and contact nothing without an out-of-band grant.
"""

__all__ = ["openbao_resolver"]
