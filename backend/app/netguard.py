"""Destination validation, SSRF defence and DNS-pinned requests (pure helpers, unit-tested)."""
from __future__ import annotations
import ipaddress, os, re, socket
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlsplit
import httpx

DEFAULT_APPROVED = ("api.render.com", "github.com", "docs.python.org")
_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*$", re.I)
_EMBEDDED = [ipaddress.ip_network(n) for n in ("64:ff9b::/96", "2002::/16", "2001::/32")]  # NAT64, 6to4, Teredo
ALLOWED_PORTS = {None, 80, 443}


class NetguardError(Exception):
    pass


def approved_domains() -> tuple:
    env = os.getenv("QYRIX_APPROVED_DOMAINS")
    return tuple(d.strip().lower() for d in env.split(",") if d.strip()) if env else DEFAULT_APPROVED


def classify_ip(ip) -> Optional[str]:
    """Return a reason if the address must never be contacted."""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return "ipv4-mapped"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast or not ip.is_global or (ip.version == 6 and any(ip in n for n in _EMBEDDED)):
        return "private/reserved"
    return None


@dataclass
class DestCheck:
    ok: bool
    reason: str            # OK | SSRF | NOT_APPROVED | INVALID
    host: Optional[str] = None
    url: Optional[str] = None


def check_http_dest(dest: str, approved: tuple) -> DestCheck:
    s = (dest or "").strip()
    if not s or any(ord(c) <= 32 or ord(c) == 127 for c in s):
        return DestCheck(False, "INVALID")
    if "://" not in s:
        s = "https://" + s
    try:
        p = urlsplit(s)
        port = p.port
        host = p.hostname
    except ValueError:
        return DestCheck(False, "INVALID")
    if p.scheme not in ("http", "https") or not host:
        return DestCheck(False, "INVALID", host)
    if p.username is not None or "@" in p.netloc:
        return DestCheck(False, "SSRF", host)            # userinfo spoofing: trusted.com@evil
    try:
        ip = ipaddress.ip_address(host)
        return DestCheck(False, "SSRF" if classify_ip(ip) else "NOT_APPROVED", str(ip))
    except ValueError:
        pass
    if _NUMERIC_HOST.match(host):                        # 2130706433, 127.1, 0x7f.1 ...
        return DestCheck(False, "SSRF", host)
    if host == "localhost" or host.endswith(".localhost"):
        return DestCheck(False, "SSRF", host)
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return DestCheck(False, "INVALID")
    if port not in ALLOWED_PORTS:
        return DestCheck(False, "NOT_APPROVED", host)
    return DestCheck(host in approved, "OK" if host in approved else "NOT_APPROVED", host, s)


def resolve_public(host: str) -> List[str]:
    """Resolve ALL A/AAAA answers; every one must be public. Raises NetguardError otherwise (fail closed)."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as e:
        raise NetguardError("dns failure") from e
    ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise NetguardError("no dns answers")
    for a in ips:
        if classify_ip(ipaddress.ip_address(a)):
            raise NetguardError("prohibited address in dns answer")
    return ips


def pinned_request(method: str, url: str, host: str, ip: str, timeout: float = 5.0) -> int:
    """Connect to the validated IP (no second DNS lookup); keep hostname for Host header + TLS SNI/verification.
    Redirects are never followed: a redirect target must be re-submitted to the gate."""
    return pinned_request_full(method, url, host, ip, timeout)[0]


def pinned_request_full(method: str, url: str, host: str, ip: str, timeout: float = 5.0):
    """Like pinned_request but also returns the redirect Location (never followed). No credentials are ever sent."""
    p = urlsplit(url)
    ipn = "[%s]" % ip if ":" in ip else ip
    target = p._replace(netloc=ipn + (":%d" % p.port if p.port else "")).geturl()
    ext = {"sni_hostname": host} if p.scheme == "https" else {}
    with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as c:
        r = c.request(method, target, headers={"Host": host}, extensions=ext)
        headers = getattr(r, "headers", None) or {}
        return r.status_code, headers.get("location")


_PROTECTED = {".env", ".ssh", ".aws", ".git", ".gnupg", "id_rsa", "id_ed25519", "credentials", "shadow", "passwd"}


def confine_path(root: str, path: str) -> bool:
    """True only if path (after symlink resolution) stays inside root and is not a protected name."""
    if not path or "\x00" in path:
        return False
    real_root = os.path.realpath(root)
    lexical = os.path.normpath(os.path.join(real_root, path))
    real = os.path.realpath(lexical)
    if os.path.commonpath([real_root, real]) != real_root:
        return False
    if real != lexical:                  # a symlink somewhere on the path: rejected for the MVP (master plan 11)
        return False
    rel = os.path.relpath(real, real_root).split(os.sep)
    return not any(part.lower() in _PROTECTED or part.lower().startswith(".env") for part in rel)
