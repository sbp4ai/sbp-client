"""Endpoint-side helper that turns SBP inner frames into E2EE envelopes.

``E2EELink`` is transport-agnostic: it produces/consumes plain dicts. The caller
ships those dicts over a WebSocket and feeds received dicts back in. The relay
never uses this class — it only verifies signatures and routes by tag.
"""
from __future__ import annotations

import time
from secrets import token_hex
from typing import Optional

from .crypto import (
    VERSION, KeyPair, KeyRing, compute_tag, sign_challenge, wrap, unwrap, SecurityError,
)


class Scope:
    """Builds the opaque routing scope strings from a device id + optional sid."""

    def __init__(self, device_did: str):
        self.did = device_did

    def device(self) -> str:
        return f"dev|{self.did}"

    def session(self, sid: str) -> str:
        return f"sid|{self.did}|{sid}"


class E2EELink:
    def __init__(
        self,
        my_kp: KeyPair,
        ring: KeyRing,
        rk: bytes,
        my_key_id: str,
        device_did: str,
        role: str = "client",
    ) -> None:
        self.kp = my_kp
        self.ring = ring
        self.rk = rk
        self.kid = my_key_id
        self.did = device_did
        self.role = role
        self.scope = Scope(device_did)

    # -- handshake
    def hello(self) -> dict:
        ts = int(time.time() * 1000)
        nonce = token_hex(8)
        sig = sign_challenge(self.kp.sign_sk, self.kid, ts, nonce)
        return {
            "v": VERSION, "id": "h1", "type": "req", "name": "hello",
            "payload": {
                "role": self.role, "keyId": self.kid, "ts": ts, "nonce": nonce,
                "sig": sig, "did": self.did,
            },
        }

    # -- subscription control (cleartext, signed)
    def _ctl(self, op: str, scope: str) -> dict:
        tag = compute_tag(self.rk, scope)
        sig = self.kp.sign_sk.sign(tag.encode("utf-8")).signature
        from .crypto import b64e

        return {"v": VERSION, "ctl": op, "tag": tag, "kid": self.kid, "sig": b64e(sig)}

    def subscribe(self, scope: str) -> dict:
        return self._ctl("sub", scope)

    def unsubscribe(self, scope: str) -> dict:
        return self._ctl("unsub", scope)

    # -- data
    def send(self, inner: dict, scope: str, peer_key_id: str) -> dict:
        env = wrap(
            inner, self.rk, self.kp,
            self.ring.box_pk(peer_key_id), scope,
            self.ring.sign_pk(peer_key_id),
        )
        env["kid"] = self.kid
        return env

    def recv(self, envelope: dict) -> dict:
        """Unwrap an incoming envelope into an inner frame (or pass through a ctl)."""
        if envelope.get("ctl"):
            return envelope
        peer_kid = envelope.get("kid")
        peer_sign = self.ring.sign_pk(peer_kid) if self.ring.has(peer_kid) else None
        return unwrap(envelope, self.rk, self.kp, expected_kid=None, peer_sign_pk=peer_sign)


__all__ = ["Scope", "E2EELink"]
