"""sbp-client: SBP E2EE crypto core + endpoint transport helper.

See ``sbp-spec/spec/SBP-0.4-e2ee.md`` for the wire format.
"""
from .crypto import (
    VERSION, KeyPair, KeyRing, derive_rk, compute_tag,
    sign_challenge, verify_challenge, wrap, unwrap, verify_sig, SecurityError,
)
from .transport import E2EELink, Scope

__all__ = [
    "VERSION", "KeyPair", "KeyRing", "derive_rk", "compute_tag",
    "sign_challenge", "verify_challenge", "wrap", "unwrap", "verify_sig",
    "SecurityError", "E2EELink", "Scope",
]
