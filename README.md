# sbp-client

SBP (Session Bridge Protocol) **end-to-end encryption core**. Implements the wire
format from [`sbp-spec/spec/SBP-0.4-e2ee.md`](https://github.com/sbp4ai/sbp-spec/blob/main/spec/SBP-0.4-e2ee.md).

The relay (`sbp-dispatcher`) never holds a secret: confidentiality comes from
`crypto_box` sealing to the *pinned* recipient box public key, and integrity from an
Ed25519 signature over `tag || eph || cipher`. Routing is blinded with
`HMAC(rk, scope)`, so the relay cannot even tell which session a frame belongs to.

## Install

```bash
pip install sbp-client
```

## Quick start

```python
from sbp_client import KeyPair, KeyRing, derive_rk, E2EELink

rk = derive_rk("your-routing-passphrase")          # 32-byte shared routing key
me = KeyPair.generate()                            # your box+sign keypair
ring = KeyRing()
ring.add("peer", peer_box_pk_b64, peer_sign_pk_b64)  # pin the other side's publics

link = E2EELink(me, ring, rk, my_key_id="cli", device_did="dev_abc", role="client")
hello = link.hello()                               # send to relay first
link.subscribe(link.scope.device())                # ask relay to route device-tag frames
envelope = link.send(inner_frame, link.scope.session("sess1"), peer_key_id="dev")
# ... ship `envelope` over WebSocket; on the other side:
inner = link.recv(envelope)                        # decrypted + signature-checked
```

## Key formats

| Field | Bytes | Note |
|---|---|---|
| `box_sk` / `box_pk` | 32 | X25519 (`crypto_box`) |
| `sign_sk` | 32 (PyNaCl seed) **or** 64 (libsodium `seed‖pk`) | both accepted by `KeyPair` |
| `sign_pk` | 32 | Ed25519 verify key |
| `rk` | 32 | 64-hex = raw key; anything else is stretched with Argon2id |

`KeyPair.to_strings()` exports `sign_sk` in the **64-byte** libsodium form, so the same
string can be pasted straight into a JS client (libsodium / tweetnacl both want 64 bytes).

## Wire format

```
envelope = { v:"sbp/0.3e", tag, kid, eph, sig, cipher }
  tag    = base64url(HMAC-SHA256(rk, scope))       scope: "dev|{did}" | "sid|{did}|{sid}"
  eph    = base64url(ephemeral X25519 public key)
  cipher = base64url(nonce[24] || crypto_box(inner))
  sig    = base64url(Ed25519.sign(sign_sk, tag || eph || cipher))
```

Every frame uses a fresh ephemeral keypair, so each `crypto_box` key is independent
(forward secrecy within a session). The relay verifies `sig` with `sign_pk` from its
public-key directory and routes by `tag` — it can do neither without `rk` / `box_sk`.

## Layout

- `sbp_client/crypto.py` — `KeyPair`, `KeyRing`, `derive_rk`, `compute_tag`,
  `wrap`/`unwrap`, `sign_challenge`/`verify_challenge`, `verify_sig`.
- `sbp_client/transport.py` — `E2EELink` / `Scope`: transport-agnostic envelope
  wrap/unwrap + subscription control, shared by `sbp-agents` and client apps.

## Related

- `sbp-dispatcher` — the relay (public-key directory + opaque-tag pub/sub).
- `sbp-agents` — the device/panel that reports local tmux / CLI sessions.
