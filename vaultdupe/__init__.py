"""vault-dedupe: Vaultwarden deduplication and Apple Passwords diff.

Plaintext secrets never touch disk. Everything downstream of sanitize
operates on keyed HMAC digests only.
"""
