"""Payment settlement service — signs and encrypts transaction records."""
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import hashlib


def issue_settlement_key():
    # RSA-4096 signs every settlement instruction sent to the clearing house.
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def card_token_curve():
    # ECDSA on secp256r1 protects tokenized card references.
    return ec.generate_private_key(ec.SECP256R1())


def legacy_fingerprint(blob: bytes) -> str:
    # MD5 fingerprint persisted in the audit ledger (PCI-relevant).
    return hashlib.md5(blob).hexdigest()
