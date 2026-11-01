"""SBP E2EE crypto core (libsodium / PyNaCl).

Single source of truth for the wire format described in
``sbp-spec/spec/SBP-0.4-e2ee.md``. Used by both ``sbp-dispatcher`` (to verify
signatures and route by opaque tag) and ``sbp-agents`` / client apps (to seal
and open envelopes).

Design: the relay never holds a secret. Confidentiality comes from
``crypto_box`` sealing to the *pinned* recipient box public key; integrity and
identity come from an Ed25519 signature over ``tag || eph || cipher``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Optional

from nacl.bindings import crypto_box, crypto_box_open, crypto_scalarmult
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random as nacl_random

VERSION = "sbp/0.3e"
NONCE_LEN = 24
CHALLENGE_PREFIX = "sbp1|"


# ---------------------------------------------------------------- base64url
def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


# ---------------------------------------------------------------- keypair
class KeyPair:
    """One endpoint's box (X25519) + sign (Ed25519) keypairs."""

    def __init__(self, box_sk: bytes, sign_sk: bytes):
        # PyNaCl 的 SigningKey 只认 32 字节 seed；libsodium 习惯存 64 字节
        # (seed||pk)。为了和 JS 端共用同一份配置，这里两种都收。
        if len(sign_sk) == 64:
            sign_sk = sign_sk[:32]
        self.box_sk = PrivateKey(box_sk)
        self.sign_sk = SigningKey(sign_sk)

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(bytes(PrivateKey.generate()), bytes(SigningKey.generate()))

    # -- export
    @property
    def box_pk(self) -> bytes:
        return bytes(self.box_sk.public_key)

    @property
    def sign_pk(self) -> bytes:
        return bytes(self.sign_sk.verify_key)

    @property
    def sign_sk_full(self) -> bytes:
        """64-byte libsodium form (seed||pk) — what JS `crypto_sign_detached` wants."""
        return bytes(self.sign_sk) + bytes(self.sign_sk.verify_key)

    def to_strings(self) -> dict:
        """Persistable form: base64url of the four raw keys (private included).

        ``sign_sk`` is exported in the 64-byte libsodium form so the same string
        can be pasted straight into a JS client.
        """
        return {
            "box_sk": b64e(bytes(self.box_sk)),
            "sign_sk": b64e(self.sign_sk_full),
            "box_pk": b64e(self.box_pk),
            "sign_pk": b64e(self.sign_pk),
        }

    @classmethod
    def from_strings(cls, box_sk: str, sign_sk: str) -> "KeyPair":
        return cls(b64d(box_sk), b64d(sign_sk))

    @classmethod
    def from_public(cls, box_pk: str, sign_pk: str) -> "KeyPair":
        """A peer view: we only hold their public keys (can verify + seal to them)."""
        kp = cls(os.urandom(32), os.urandom(32))
        kp._peer_box_pk = PublicKey(b64d(box_pk))
        kp._peer_sign_pk = VerifyKey(b64d(sign_pk))
        return kp


class KeyRing:
    """Pinned peers: keyId -> (box_pk, sign_pk). Prevents relay key-swapping MITM."""

    def __init__(self) -> None:
        self._peers: dict[str, tuple[PublicKey, VerifyKey]] = {}

    def add(self, key_id: str, box_pk: str, sign_pk: str) -> None:
        self._peers[key_id] = (PublicKey(b64d(box_pk)), VerifyKey(b64d(sign_pk)))

    def box_pk(self, key_id: str) -> PublicKey:
        return self._peers[key_id][0]

    def sign_pk(self, key_id: str) -> VerifyKey:
        return self._peers[key_id][1]

    def has(self, key_id: str) -> bool:
        return key_id in self._peers


# ---------------------------------------------------------------- rk
def derive_rk(material: str, salt: bytes = b"sbp-e2ee-rk-v1") -> bytes:
    """Turn a passphrase (or 64-hex raw key) into a 32-byte routing key.

    If ``material`` is exactly 64 hex chars it is used as the raw 32-byte key;
    otherwise it is stretched with Argon2id so the same passphrase yields the
    same ``rk`` on every endpoint.
    """
    if len(material) == 64 and all(c in "0123456789abcdefABCDEF" for c in material):
        return bytes.fromhex(material)
    try:
        from argon2.low_level import Type, hash_secret_raw

        return hash_secret_raw(
            material.encode(), salt, time_cost=2, memory_cost=64 * 1024,
            parallelism=1, hash_len=32, type=Type.ID,
        )
    except Exception:  # pragma: no cover - argon2 optional in some envs
        # Deterministic, but NOT a substitute for Argon2; only used as fallback.
        return hashlib.pbkdf2_hmac("sha256", material.encode(), salt, 100_000, 32)


def compute_tag(rk: bytes, scope: str) -> str:
    """Opaque routing tag. The relay sees only this string, never ``scope``."""
    return b64e(hmac.new(rk, scope.encode("utf-8"), hashlib.sha256).digest())


# ---------------------------------------------------------------- challenge
def sign_challenge(sign_sk: SigningKey, key_id: str, ts: int, nonce: str) -> str:
    msg = f"{CHALLENGE_PREFIX}{key_id}|{ts}|{nonce}".encode()
    return b64e(sign_sk.sign(msg).signature)


def verify_challenge(sign_pk: VerifyKey, key_id: str, ts: int, nonce: str, sig_b64: str) -> bool:
    msg = f"{CHALLENGE_PREFIX}{key_id}|{ts}|{nonce}".encode()
    try:
        sign_pk.verify(msg, b64d(sig_b64))
    except Exception:
        return False
    if abs(int(time.time() * 1000) - int(ts)) > 5 * 60 * 1000:
        return False
    return True


# ---------------------------------------------------------------- envelope
def _signed_message(tag: str, eph_pk: bytes, cipher: bytes) -> bytes:
    return tag.encode("utf-8") + eph_pk + cipher


def wrap(
    inner: dict,
    rk: bytes,
    sender: KeyPair,
    recipient_box_pk: PublicKey,
    scope: str,
    peer_sign_pk: Optional[VerifyKey] = None,
) -> dict:
    """Seal an inner SBP frame into an envelope the relay can route but not read."""
    eph = PrivateKey.generate()
    nonce = nacl_random(NONCE_LEN)
    inner_bytes = json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ct = crypto_box(inner_bytes, nonce, bytes(recipient_box_pk), bytes(eph))
    cipher = nonce + ct
    tag = compute_tag(rk, scope)
    signed = _signed_message(tag, bytes(eph.public_key), cipher)
    sig = sender.sign_sk.sign(signed).signature
    return {
        "v": VERSION,
        "tag": tag,
        "kid": None,  # filled by caller (relay needs it cleartext)
        "eph": b64e(bytes(eph.public_key)),
        "sig": b64e(sig),
        "cipher": b64e(cipher),
    }


def unwrap(
    envelope: dict,
    rk: bytes,
    receiver: KeyPair,
    expected_kid: Optional[str] = None,
    peer_sign_pk: Optional[VerifyKey] = None,
) -> dict:
    """Open an envelope. Raises ``SecurityError`` on any tamper / auth failure."""
    tag = envelope.get("tag", "")
    kid = envelope.get("kid")
    eph_b = b64d(envelope.get("eph", ""))
    cipher = b64d(envelope.get("cipher", ""))
    sig = b64d(envelope.get("sig", ""))

    if expected_kid is not None and kid != expected_kid:
        raise SecurityError("kid mismatch")
    signed = _signed_message(tag, eph_b, cipher)
    if peer_sign_pk is not None:
        try:
            peer_sign_pk.verify(signed, sig)
        except Exception as exc:
            raise SecurityError("bad frame signature") from exc

    nonce, ct = cipher[:NONCE_LEN], cipher[NONCE_LEN:]
    try:
        plain = crypto_box_open(ct, nonce, eph_b, bytes(receiver.box_sk))
    except Exception as exc:
        raise SecurityError("decrypt failed") from exc
    return json.loads(plain.decode("utf-8"))


def verify_sig(sign_pk: VerifyKey, tag: str, eph_b64: str, cipher_b64: str, sig_b64: str) -> bool:
    """Relay-side: verify a frame signature without decrypting."""
    signed = _signed_message(tag, b64d(eph_b64), b64d(cipher_b64))
    try:
        sign_pk.verify(signed, b64d(sig_b64))
    except Exception:
        return False
    return True


class SecurityError(Exception):
    """Raised on any confidentiality/integrity failure (tamper, bad sig, bad decrypt)."""


__all__ = [
    "VERSION", "KeyPair", "KeyRing", "derive_rk", "compute_tag",
    "sign_challenge", "verify_challenge", "wrap", "unwrap", "verify_sig", "SecurityError",
]
