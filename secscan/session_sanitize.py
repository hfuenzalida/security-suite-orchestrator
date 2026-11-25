"""Strip live auth/session material before checkpoint or report persistence."""

from __future__ import annotations

import copy
from typing import Any


def _scrub_auth_session(session: dict[str, Any]) -> None:
    if "cookies" in session:
        session["cookies"] = {}
    if "headers" in session:
        session["headers"] = {}
    if "storage_state" in session:
        session["storage_state"] = None


def strip_session_secrets(obj: Any) -> Any:
    """
    Deep-copy and remove reusable session secrets from phase payloads.

    Keeps counts / status / step logs; clears cookie values, auth headers,
    Playwright storage paths, and chain-captured token values.
    """
    out = copy.deepcopy(obj)
    if not isinstance(out, dict):
        return out

    phases = out.get("phases")
    if isinstance(phases, dict):
        auth = phases.get("auth")
        if isinstance(auth, dict):
            sess = auth.get("session")
            if isinstance(sess, dict):
                _scrub_auth_session(sess)
        chain = phases.get("chain")
        if isinstance(chain, dict) and "captured" in chain:
            names = sorted(str(k) for k in (chain.get("captured") or {}) if k)
            chain["captured"] = {}
            chain["captured_vars"] = names

    # Also accept a bare phases dict
    if "auth" in out and "phases" not in out:
        sess = out.get("auth", {}).get("session") if isinstance(out.get("auth"), dict) else None
        if isinstance(sess, dict):
            _scrub_auth_session(sess)
        chain = out.get("chain")
        if isinstance(chain, dict) and "captured" in chain:
            names = sorted(str(k) for k in (chain.get("captured") or {}) if k)
            chain["captured"] = {}
            chain["captured_vars"] = names

    return out
