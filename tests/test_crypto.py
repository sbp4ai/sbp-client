"""Round-trip + tamper tests for the SBP E2EE core."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbp_client import (  # noqa: E402
    KeyPair, KeyRing, derive_rk, compute_tag,
    sign_challenge, verify_challenge, wrap, unwrap, verify_sig, SecurityError, E2EELink,
)
from sbp_client.crypto import b64e, b64d

RK = derive_rk("demo-rk-passphrase-not-secret")


def make_pair(kid):
    kp = KeyPair.generate()
    ring = KeyRing()
    ring.add(kid, b64e(kp.box_pk), b64e(kp.sign_pk))
    return kp, ring


def cross_pin(a_kp, a_ring, b_kp, b_ring, a_id="a", b_id="b"):
    a_ring.add(b_id, b64e(b_kp.box_pk), b64e(b_kp.sign_pk))
    b_ring.add(a_id, b64e(a_kp.box_pk), b64e(a_kp.sign_pk))


def test_roundtrip():
    dev_kp, dev_ring = make_pair("dev")
    cli_kp, cli_ring = make_pair("cli")
    cross_pin(dev_kp, dev_ring, cli_kp, cli_ring, "dev", "cli")
    scope = "sid|dev_abc|sess1"
    inner = {"type": "req", "name": "session.answer", "sid": "sess1",
             "payload": {"pid": "a1", "choice": 2, "secret": "TOP-SECRET-PROMPT"}}
    env = wrap(inner, RK, cli_kp, dev_ring.box_pk("dev"), scope, cli_ring.sign_pk("dev"))
    env["kid"] = "cli"
    # relay can read only tag/kid/eph/sig/cipher, never `secret`
    assert "TOP-SECRET" not in json.dumps(env)
    assert verify_sig(dev_ring.sign_pk("cli"), env["tag"], env["eph"], env["cipher"], env["sig"])
    opened = unwrap(env, RK, dev_kp, expected_kid="cli", peer_sign_pk=dev_ring.sign_pk("cli"))
    assert opened["payload"]["secret"] == "TOP-SECRET-PROMPT"
    assert compute_tag(RK, scope) == compute_tag(RK, scope)
    assert compute_tag(RK, scope) != compute_tag(RK, "sid|dev_abc|sess2")
    print("test_roundtrip OK")


def test_tamper():
    dev_kp, dev_ring = make_pair("dev")
    cli_kp, cli_ring = make_pair("cli")
    cross_pin(dev_kp, dev_ring, cli_kp, cli_ring, "dev", "cli")
    scope = "sid|dev_abc|s1"
    inner = {"type": "evt", "name": "session.message", "payload": {"text": "hi"}}
    env = wrap(inner, RK, cli_kp, dev_ring.box_pk("dev"), scope, cli_ring.sign_pk("dev"))
    env["kid"] = "cli"
    bad = dict(env)
    c = bytearray(b64d(bad["cipher"]))
    c[-1] ^= 1
    bad["cipher"] = b64e(bytes(c))
    try:
        unwrap(bad, RK, dev_kp, expected_kid="cli", peer_sign_pk=dev_ring.sign_pk("cli"))
        raise AssertionError("should have raised")
    except SecurityError:
        pass
    print("test_tamper OK")


def test_challenge():
    import time as _t
    kp, ring = make_pair("dev")
    ts, nonce = int(_t.time() * 1000), "abc"
    sig = sign_challenge(kp.sign_sk, "dev", ts, nonce)
    assert verify_challenge(ring.sign_pk("dev"), "dev", ts, nonce, sig)
    assert not verify_challenge(ring.sign_pk("dev"), "dev", ts, "wrong", sig)
    print("test_challenge OK")


def test_link():
    dev_kp, dev_ring = make_pair("dev")
    cli_kp, cli_ring = make_pair("cli")
    cross_pin(dev_kp, dev_ring, cli_kp, cli_ring, "dev", "cli")
    cli = E2EELink(cli_kp, cli_ring, RK, "cli", "dev_abc", role="client")
    dev = E2EELink(dev_kp, dev_ring, RK, "dev", "dev_abc", role="device")
    inner = {"type": "req", "name": "session.attach", "sid": "s1", "payload": {}}
    env = cli.send(inner, cli.scope.session("s1"), "dev")
    got = dev.recv(env)
    assert got["name"] == "session.attach"
    reply = {"type": "res", "name": "session.attach", "payload": {"ok": True}}
    env2 = dev.send(reply, dev.scope.session("s1"), "cli")
    got2 = cli.recv(env2)
    assert got2["payload"]["ok"] is True
    # subscription control frame is signed and carries the opaque tag
    sub = cli.subscribe(cli.scope.device())
    assert sub["ctl"] == "sub" and sub["tag"] == compute_tag(RK, "dev|dev_abc")
    print("test_link OK")


if __name__ == "__main__":
    test_roundtrip()
    test_tamper()
    test_challenge()
    test_link()
    print("ALL OK")
