"""Ed25519 keys (PyCA `cryptography`, already a pinned dependency). Private keys are PEM (PKCS#8, unencrypted, file
mode 0600); public keys travel as base64 of the 32 raw bytes. key_id = "ed25519:" + first 32 hex of SHA-256(raw)."""
import base64
import hashlib
import os
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class KeyError_(Exception):
    pass


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def unb64(s: str) -> bytes:
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except Exception:
        raise KeyError_("invalid base64") from None


def raw_public(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id_of_raw(raw: bytes) -> str:
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:32]


def public_from_b64(s: str) -> Ed25519PublicKey:
    raw = unb64(s)
    if len(raw) != 32:
        raise KeyError_("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def generate() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_pem(k: Ed25519PrivateKey) -> bytes:
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def load_private(path: str) -> Ed25519PrivateKey:
    try:
        with open(path, "rb") as f:
            k = serialization.load_pem_private_key(f.read(), password=None)
    except Exception:
        raise KeyError_("private key file not readable or not PEM") from None   # never echo key material
    if not isinstance(k, Ed25519PrivateKey):
        raise KeyError_("not an Ed25519 private key")
    return k


def write_private(path: str, k: Ed25519PrivateKey) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_pem(k))


def describe(k: Ed25519PrivateKey) -> Tuple[str, str]:
    raw = raw_public(k.public_key())
    return key_id_of_raw(raw), b64(raw)


def sign(k: Ed25519PrivateKey, msg: bytes) -> str:
    return b64(k.sign(msg))


def verify(pub: Ed25519PublicKey, sig_b64: str, msg: bytes) -> bool:
    try:
        sig = unb64(sig_b64)
        if len(sig) != 64:
            return False
        pub.verify(sig, msg)
        return True
    except (InvalidSignature, KeyError_, ValueError):
        return False
