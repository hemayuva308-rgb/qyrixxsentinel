"""Controlled Tool Adapter.

The adapter is the ONLY component that performs a tool action, and it only runs for a server-side gate evaluation with
a valid, unused grant (see gateway.execute_grant). It never receives client-supplied parameters: it is handed the
immutable parameters that were stored when the Gate decided ALLOW.

- HttpAdapter : resolves the host, rejects any private/reserved answer (all A/AAAA), connects to the pinned IP with the
                original hostname for Host/SNI/certificate checks, never follows redirects, sends no credentials.
                A 3xx response is returned as a redirect that must go through a fresh Gate evaluation + grant.
- FileAdapter : descriptor-relative read inside the workspace jail: every path component is opened with O_NOFOLLOW
                relative to its parent directory fd (no symlinks, no traversal, no TOCTOU between check and open),
                regular files only, streamed with a 1 MB hard limit. Content is redacted before it is returned.
- SandboxAdapter : used ONLY by the public demo. Performs no I/O at all and returns a fixed fixture.
"""
import os
import stat
from typing import Callable, Dict
from urllib.parse import urljoin, urlsplit

from app import netguard

MAX_FILE_BYTES = 1024 * 1024


class AdapterError(Exception):
    pass


def read_jailed(root: str, rel: str, limit: int = MAX_FILE_BYTES) -> bytes:
    if not rel or "\x00" in rel or os.path.isabs(rel):
        raise AdapterError("path not allowed")
    parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        raise AdapterError("path not allowed")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise AdapterError("platform lacks O_NOFOLLOW/O_DIRECTORY; file jail refuses to run")
    fds = [os.open(root, os.O_RDONLY | directory)]
    try:
        for p in parts[:-1]:
            fds.append(os.open(p, os.O_RDONLY | directory | nofollow, dir_fd=fds[-1]))
        fd = os.open(parts[-1], os.O_RDONLY | nofollow, dir_fd=fds[-1])
        fds.append(fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AdapterError("not a regular file")
        chunks, total = [], 0
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            total += len(b)
            if total > limit:
                raise AdapterError("file exceeds 1 MB limit")
            chunks.append(b)
        return b"".join(chunks)
    except OSError as e:            # ELOOP (symlink), ENOENT, ENOTDIR ... never leak paths
        raise AdapterError("file not readable") from None
    finally:
        for f in reversed(fds):
            os.close(f)


class HttpAdapter:
    name = "http"

    def __init__(self, approved: Callable[[], tuple] = None):
        self.approved = approved or netguard.approved_domains   # per-tenant allowlist (never another tenant's)

    def __call__(self, params: Dict) -> Dict:
        chk = netguard.check_http_dest(params["dest"], self.approved())
        if not chk.ok:                                   # re-validated at execution time (policy may have changed)
            raise AdapterError("destination no longer allowed")
        ips = netguard.resolve_public(chk.host)          # all answers validated; NetguardError propagates
        status, location = netguard.pinned_request_full(params["method"], chk.url, chk.host, ips[0])
        out = {"status": status, "pinned_ip": ips[0], "host": chk.host}
        if location and 300 <= status < 400:
            nxt = urljoin(chk.url, location)
            cross = urlsplit(nxt).hostname != chk.host
            out["redirect"] = {"location": nxt, "cross_host": cross, "requires_gate": True,
                               "note": "not followed: submit the redirect target to the Gate with redirect_of"}
        return out


class FileAdapter:
    name = "file.read"

    def __init__(self, root: str, redact: Callable[[str], str]):
        self.root, self.redact = root, redact

    def __call__(self, params: Dict) -> Dict:
        data = read_jailed(self.root, params["dest"])
        return {"bytes": len(data), "content": self.redact(data.decode("utf-8", errors="replace"))}


class SandboxAdapter:
    """Demo only: no network, no filesystem, no subprocess. Returns a fixed, clearly labelled fixture."""
    name = "sandbox"

    def __call__(self, params: Dict) -> Dict:
        return {"sandbox": True, "status": 200, "fixture": "SIMULATED tool response (no real request was made)",
                "tool": params["tool"], "method": params["method"]}
