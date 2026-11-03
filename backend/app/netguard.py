"""Destination validation, SSRF defence and DNS-pinned requests (pure helpers, unit-tested)."""
from __future__ import annotations
import http.client, ipaddress, os, re, socket, ssl, unicodedata
from dataclasses import dataclass
from typing import List, Optional, Tuple
import idna                                              # IDNA2008 (RFC 5891-5893); pinned via requirements-lock
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


# ---------------- strict hostname canonicalization (v1.5, R20) ----------------
# Characters that are not label separators in DNS but that IDNA2003/UTS-46 processing silently turns into "." or removes.
_LOOKALIKE_DOTS = frozenset("\u3002\uff0e\uff61\u2024\ufe52\u2e3c\u0701\u0702\u06d4")
_SCRIPT_GROUPS = ({"HAN", "HIRAGANA", "KATAKANA"}, {"HAN", "HANGUL"}, {"HAN", "BOPOMOFO"})


def _script(ch: str) -> Optional[str]:
    """Coarse Unicode script of a character, or None for script-neutral characters (digits, hyphen, combining marks)."""
    if ch.isascii() and not ch.isalpha():
        return None
    if unicodedata.category(ch).startswith("M"):
        return None                                      # combining marks inherit the base character's script
    name = unicodedata.name(ch, "")
    head = name.split(" ")[0]
    if head == "CJK":
        return "HAN"
    if head.startswith("KATAKANA-HIRAGANA"):
        return "KATAKANA"
    return head or "UNKNOWN"


def _single_script(label: str) -> bool:
    scripts = {s for s in (_script(c) for c in label) if s}
    return len(scripts) <= 1 or any(scripts <= grp for grp in _SCRIPT_GROUPS)


def canonical_host(raw: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (ascii_a_label_host, None) or (None, reason). Deliberately strict and unambiguous:
    * invisible / format / control / space / private-use / unassigned characters  -> DECEPTIVE
    * look-alike dots (fullwidth, ideographic, halfwidth ...)                       -> DECEPTIVE
    * compatibility forms (fullwidth letters etc., NFKC != input) or non-NFC text   -> DECEPTIVE
    * a label mixing scripts (e.g. Latin + Cyrillic)                                -> DECEPTIVE
    * anything IDNA2008 (RFC 5891 + contextual + bidi rules) refuses, malformed punycode, bad lengths -> INVALID
    Genuine single-script internationalised names are accepted and returned as their A-label (xn--...)."""
    if not raw or len(raw) > 253:
        return None, "INVALID"
    for ch in raw:
        if unicodedata.category(ch) in ("Cf", "Cc", "Cs", "Co", "Cn", "Zs", "Zl", "Zp"):
            return None, "DECEPTIVE"
        if ch in _LOOKALIKE_DOTS:
            return None, "DECEPTIVE"
    if unicodedata.normalize("NFKC", raw) != raw or unicodedata.normalize("NFC", raw) != raw:
        return None, "DECEPTIVE"
    out = []
    for label in raw.split("."):
        if not label or len(label) > 63:
            return None, "INVALID"
        if label.isascii():
            lab = label.lower()
            if not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?", lab):
                return None, "INVALID"
            if lab[2:4] == "--" and not lab.startswith("xn--"):
                return None, "INVALID"                   # reserved R-LDH labels other than xn--
            if lab.startswith("xn--"):
                try:
                    u = idna.decode(lab)
                    if idna.encode(u).decode("ascii") != lab:
                        return None, "INVALID"
                except (idna.IDNAError, UnicodeError):
                    return None, "INVALID"
                if not _single_script(u):
                    return None, "DECEPTIVE"
            out.append(lab)
        else:
            if not _single_script(label):
                return None, "DECEPTIVE"
            try:
                out.append(idna.encode(label, uts46=False).decode("ascii"))
            except (idna.IDNAError, UnicodeError):
                return None, "INVALID"
    host = ".".join(out)
    return (host, None) if len(host) <= 253 else (None, "INVALID")


def _display(raw: str) -> str:
    """Unambiguous ASCII rendering of a refused hostname for logs/proofs (invisible characters become visible)."""
    return raw.encode("ascii", "backslashreplace").decode("ascii")[:255]


def _canonical_set(approved: tuple) -> frozenset:
    out = set()
    for d in approved or ():
        h, _ = canonical_host((d or "").strip().lower().rstrip("."))
        if h:
            out.add(h)
    return frozenset(out)


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
    canon, why = canonical_host(host)
    if canon is None:
        return DestCheck(False, "DECEPTIVE_HOST" if why == "DECEPTIVE" else "INVALID", _display(host))
    host = canon                                         # the ONLY form used for policy, logs, proofs and approvals
    if port not in ALLOWED_PORTS:
        return DestCheck(False, "NOT_APPROVED", host)
    ok = host in _canonical_set(approved)
    return DestCheck(ok, "OK" if ok else "NOT_APPROVED", host, s)


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


_EXEC_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_ALABEL = re.compile(r"^[a-z0-9.-]{1,253}$")


class _PinnedTunnel(http.client.HTTPSConnection):
    """CONNECT <pinned-ip>:<port> through the egress proxy, then TLS with SNI + certificate check for the HOSTNAME.
    (http.client/httpcore would use the CONNECT target - the IP - as TLS server name.)"""

    def __init__(self, proxy_host, proxy_port, ip, port, sni_host, tunnel_headers, timeout, context):
        super().__init__(proxy_host, proxy_port, timeout=timeout, context=context)
        self.set_tunnel(ip, port, headers=tunnel_headers)
        self._sni_host = sni_host

    def connect(self):
        http.client.HTTPConnection.connect(self)          # TCP to the proxy, then CONNECT (self._tunnel)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self._sni_host)


def _proxied_request(method: str, url: str, host: str, ip: str, proxy: str, execution_id: Optional[str],
                     timeout: float, ssl_context=None):
    """Phase C2 (design §4, §7.5 + the approved pinned-IP decision): the Gate's SSRF pinning is unchanged - the proxy is
    asked to connect to the IP this process resolved and validated, never to resolve the name itself. The hostname
    and execution id travel as X-Qyrix-Host / X-Qyrix-Execution on the CONNECT request (visible without TLS
    termination); for plain HTTP they are request headers to the proxy. One connection per execution, no pooling."""
    if not _ALABEL.match(host) or (execution_id is not None and not _EXEC_ID.match(execution_id)):
        raise NetguardError("invalid proxy tagging")
    px = urlsplit(proxy)
    if px.scheme != "http" or not px.hostname:
        raise NetguardError("QYRIX_EGRESS_PROXY_URL must be http://host:port")
    p = urlsplit(url)
    tags = {"X-Qyrix-Host": host}
    if execution_id:
        tags["X-Qyrix-Execution"] = execution_id
    path = (p.path or "/") + ("?" + p.query if p.query else "")
    ipn = "[%s]" % ip if ":" in ip else ip
    if p.scheme == "https":
        ctx = ssl_context or ssl.create_default_context(cafile=_ca_bundle())
        conn = _PinnedTunnel(px.hostname, px.port or 3128, ip, p.port or 443, host, tags, timeout, ctx)
        headers = {"Host": host}
        target = path
    else:
        conn = http.client.HTTPConnection(px.hostname, px.port or 3128, timeout=timeout)
        headers = {"Host": host, **tags}
        target = "http://%s%s%s" % (ipn, ":%d" % p.port if p.port else "", path)
    try:
        conn.request(method, target, headers=headers)
        r = conn.getresponse()
        return r.status, r.getheader("location")
    finally:
        conn.close()


def _ca_bundle() -> Optional[str]:
    try:
        import certifi
        return certifi.where()
    except Exception:
        return None


def pinned_request_full(method: str, url: str, host: str, ip: str, timeout: float = 5.0, proxy: Optional[str] = None,
                        execution_id: Optional[str] = None):
    """Like pinned_request but also returns the redirect Location (never followed). No credentials are ever sent.
    With `proxy` (QYRIX_EGRESS_PROXY_URL), the same pinned connection goes through the egress proxy (see above)."""
    if proxy:
        return _proxied_request(method, url, host, ip, proxy, execution_id, timeout)
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
