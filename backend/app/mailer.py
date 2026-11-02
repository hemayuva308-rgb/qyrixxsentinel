"""E-mail integration BOUNDARY (v1.4). Qyrix Sentinel does not run an SMTP client. When configured, it POSTs a signed
JSON message to an operator-run mail relay inside the trusted network, which renders and sends the e-mail.

    QYRIX_MAIL_WEBHOOK_URL          https://mail-relay.internal/send      (unset => NOT CONFIGURED: nothing is ever sent)
    QYRIX_MAIL_WEBHOOK_SECRET_FILE  file with >= 32 chars; HMAC-SHA256 of the body in header X-Qyrix-Signature
    QYRIX_PUBLIC_URL                https://sentinel.example.com          (links in e-mails)

When not configured: invitations and admin-issued password resets return their single-use token ONCE to the
authorised admin for out-of-band delivery; self-service "forgot password" sends nothing (and says the same thing for
existing and non-existing accounts). The relay receives single-use tokens: it is part of the trust boundary.
"""
import hashlib
import hmac
import json
import os
from typing import Dict

from app import observability as obs


def configured() -> bool:
    return bool(os.getenv("QYRIX_MAIL_WEBHOOK_URL", "").strip()) and bool(_secret())


def _secret() -> bytes:
    p = os.getenv("QYRIX_MAIL_WEBHOOK_SECRET_FILE", "").strip()
    try:
        s = open(p, "rb").read().strip() if p else b""
    except OSError:
        return b""
    return s if len(s) >= 32 and b"CHANGE_ME" not in s else b""


def _link(kind: str, payload: Dict) -> str:
    base = os.getenv("QYRIX_PUBLIC_URL", "").rstrip("/")
    path = {"invitation": "/invite", "password_reset": "/reset"}[kind]
    return "%s%s#token=%s" % (base, path, payload["token"])        # fragment: never sent to servers / proxies in logs


def _transport(url: str, body: bytes, headers: Dict[str, str]) -> int:
    import httpx
    return httpx.post(url, content=body, headers=headers, timeout=5.0).status_code


def send(kind: str, to: str, payload: Dict) -> bool:
    if not configured():
        return False
    msg = {"kind": kind, "to": to, "link": _link(kind, payload),
           **{k: v for k, v in payload.items() if k in ("tenant", "role")}}
    body = json.dumps(msg, sort_keys=True).encode()
    sig = hmac.new(_secret(), body, hashlib.sha256).hexdigest()
    try:
        ok = 200 <= _transport(os.environ["QYRIX_MAIL_WEBHOOK_URL"], body,
                               {"content-type": "application/json", "x-qyrix-signature": sig}) < 300
    except Exception:
        ok = False
    obs.inc("qyrix_mail_deliveries_total", kind=kind, ok=str(ok).lower())
    if not ok:
        obs.event("mail_delivery_failed", severity="warning", kind=kind)
    return ok
