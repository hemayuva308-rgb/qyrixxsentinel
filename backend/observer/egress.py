"""C5 observer sensors on the egress chokepoint (design §7.1, §7.3-§7.6, approved pinned-IP amendment).

EgressProxy   the ONLY route from the backend to the outside (under docker-compose.observer.yml):
              - CONNECT <pinned-ip>:<port> with X-Qyrix-Host (A-label) [+ X-Qyrix-Execution (uuid4)]:
                the CONNECT IP must be in the OBSERVER'S OWN resolution of X-Qyrix-Host, the TLS ClientHello SNI
                (peeked, no TLS termination) must equal X-Qyrix-Host, destinations must be public (or explicitly
                allowed CIDRs), one tunnel per execution id (DB-enforced => EXECUTION_ID_REUSE), lifetime T_tunnel.
              - untagged CONNECT / plain HTTP (other backend clients): mediated and recorded, never trusted.
              - plain HTTP absolute-form: request-level observation; X-Qyrix-* / Proxy-* headers stripped upstream.
              Every tunnel is recorded at OPEN and at CLOSE (lifecycle, bytes), so a crash mid-tunnel still leaves the
              open record (window closure treats it as still open).
DnsForwarder  UDP resolver the backend is pointed at (`dns:`); records every query (E3), forwards to an upstream.
              DNS over TCP / DoT / DoH from the backend is not a mediated channel (no route): it is tested by the
              attestor, not forwarded here.
Sink          observer-controlled listeners on the observer's EXTERNAL side used only by coverage attestation: any
              token that reaches them proves a path. Direct-path tokens must never arrive; the positive control
              (sent through the proxy) must.
All records are observer-originated (E3) and append-only (O004)."""
import ipaddress
import json
import re
import secrets
import socket
import socketserver
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from observer import ledger
from observer.db import DbError

EXEC_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
ALABEL_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
TOKEN_RE = re.compile(rb"qxtok[-/ _]([0-9a-f]{32})")
MAX_HEAD = 8192
T_TUNNEL = 30.0


def _dt(t: float) -> datetime:
    return datetime.fromtimestamp(t, timezone.utc)


def parse_sni(data: bytes) -> Optional[str]:
    """SNI host_name from a TLS ClientHello record; None if absent or malformed (no TLS termination)."""
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        n = int.from_bytes(data[3:5], "big")
        rec = data[5:5 + n]
        if not rec or rec[0] != 0x01:
            return None
        p = 4 + 2 + 32                                   # handshake header, client_version, random
        p += 1 + rec[p]                                  # session id
        p += 2 + int.from_bytes(rec[p:p + 2], "big")     # cipher suites
        p += 1 + rec[p]                                  # compression methods
        end = p + 2 + int.from_bytes(rec[p:p + 2], "big")
        p += 2
        while p + 4 <= end:
            et, el = int.from_bytes(rec[p:p + 2], "big"), int.from_bytes(rec[p + 2:p + 4], "big")
            if et == 0:                                  # server_name
                q = p + 4 + 2
                if rec[q] == 0:
                    ln = int.from_bytes(rec[q + 1:q + 3], "big")
                    return rec[q + 3:q + 3 + ln].decode("ascii").lower()
                return None
            p += 4 + el
    except (IndexError, UnicodeDecodeError):
        return None
    return None


class Recorder:
    """Writes egress evidence (O004) and throttled ledger alerts. A failure to record is counted, never silent."""

    def __init__(self, observer):
        self.obs, self.db = observer, observer.db
        self.counters: Dict[str, int] = {}
        self._last: Dict[str, float] = {}
        self._lock = threading.Lock()

    def count(self, k: str) -> None:
        with self._lock:
            self.counters[k] = self.counters.get(k, 0) + 1

    def insert(self, row: Dict) -> bool:
        cols = ["observation_id", "sensor", "kind", "observed_at"] + [k for k in (
            "tunnel_id", "closed_at", "peer", "host", "sni", "dest_ip", "dest_port", "execution_id", "method", "path_sha256",
            "qname", "qtype", "token_sha256", "bytes_in", "bytes_out", "reason") if row.get(k) is not None]
        vals = [row.get("observation_id") or str(uuid.uuid4()), row["sensor"], row["kind"], _dt(row["observed_at"])] + [
            _dt(row[k]) if k == "closed_at" else row[k] for k in cols[4:]]

        def go(cur):
            cur.execute("INSERT INTO egress_observations (%s) VALUES (%s)" % (", ".join(cols), ", ".join(["%s"] * len(cols))),
                        vals)
        try:
            self.db.run(go, lock=False)
            return True
        except DbError as e:
            if "UniqueViolation" in str(e):
                raise
            self.count("unrecorded")
            return False

    def alert(self, code: str, detail: Dict, now: float) -> None:
        with self._lock:
            if now - self._last.get(code, -1e18) < 60:
                self.counters["alerts_throttled"] = self.counters.get("alerts_throttled", 0) + 1
                return
            self._last[code] = now
        try:
            self.db.run(lambda cur: ledger.append(cur, self.obs.signer, now, "alert", code, None, None, None, detail))
        except (DbError, ledger.LedgerError):
            self.count("unrecorded")


def default_resolve(host: str) -> List[str]:
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
    except OSError:
        return []


class EgressProxy:
    def __init__(self, recorder: Recorder, host: str, port: int, resolve: Callable[[str], List[str]] = default_resolve,
                 allow_cidrs: Iterable[str] = (), t_tunnel: float = T_TUNNEL, max_concurrency: int = 64,
                 clock: Callable[[], float] = time.time):
        self.rec, self.resolve, self.t_tunnel, self.clock = recorder, resolve, t_tunnel, clock
        self.allow = [ipaddress.ip_network(c, strict=False) for c in allow_cidrs]
        self.open_tunnels: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        slots = threading.BoundedSemaphore(max_concurrency)
        proxy = self

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                if not slots.acquire(blocking=False):
                    proxy.rec.count("busy")
                    return
                try:
                    proxy._handle(self.request, self.client_address[0])
                except Exception:
                    proxy.rec.count("handler_error")
                finally:
                    slots.release()

        class S(socketserver.ThreadingMixIn, socketserver.TCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = S((host, port), H)
        self.host, self.port = self.server.server_address[:2]
        threading.Thread(target=self.server.serve_forever, name="observer-egress-proxy", daemon=True).start()

    def close(self):
        self.server.shutdown(); self.server.server_close()

    # -- policy
    def _dest_allowed(self, ip: str) -> bool:
        a = ipaddress.ip_address(ip)
        return a.is_global or any(a in n for n in self.allow)

    def _refuse(self, conn, peer, reason, status=403, **kw):
        now = self.clock()
        self.rec.insert({"sensor": "egress_proxy", "kind": "refused", "observed_at": now, "peer": peer, "reason": reason, **kw})
        self.rec.alert("EGRESS_REFUSED", {"reason": reason}, now)
        try:
            conn.sendall(b"HTTP/1.1 %d Refused\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" % status)
        except OSError:
            pass

    def _read_head(self, conn) -> Tuple[bytes, bytes]:
        conn.settimeout(10)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = conn.recv(4096)
            if not d:
                break
            buf += d
            if len(buf) > MAX_HEAD:
                raise ValueError("head too large")
        head, _, rest = buf.partition(b"\r\n\r\n")
        return head, rest

    def _tags(self, headers: Dict[str, str]):
        xhost, xexec = headers.get("x-qyrix-host"), headers.get("x-qyrix-execution")
        if xhost is not None and not ALABEL_RE.match(xhost):
            return None, None, "INVALID_X_QYRIX_HOST"
        if xexec is not None and not EXEC_RE.match(xexec):
            return None, None, "INVALID_X_QYRIX_EXECUTION"
        if xexec is not None and xhost is None:
            return None, None, "EXECUTION_WITHOUT_HOST"
        return xhost, xexec, None

    def _target_ip(self, host: str, xhost: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        h = host[1:-1] if host.startswith("[") else host
        try:
            ip = str(ipaddress.ip_address(h))
        except ValueError:
            if xhost is not None:
                return None, "TAGGED_CONNECT_MUST_USE_PINNED_IP"
            ips = self.resolve(h.lower())                # untagged client: observer resolves (never the backend's word)
            if not ips:
                return None, "UNRESOLVABLE"
            ip = ips[0]
        if xhost is not None and ip not in self.resolve(xhost):
            return None, "IP_NOT_IN_HOST_RESOLUTION"     # backend pinned an IP the host does not resolve to
        if not self._dest_allowed(ip):
            return None, "DESTINATION_NOT_ALLOWED"
        return ip, None

    def _handle(self, conn, peer: str) -> None:
        try:
            head, rest = self._read_head(conn)
            lines = head.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
        except (ValueError, OSError, UnicodeDecodeError):
            self.rec.count("malformed")
            return
        headers = {}
        for l in lines[1:]:
            if ":" in l:
                k, v = l.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        xhost, xexec, bad = self._tags(headers)
        if bad:
            return self._refuse(conn, peer, bad, 400)
        if method.upper() == "CONNECT":
            return self._connect(conn, peer, target, xhost, xexec, rest)
        return self._http(conn, peer, method.upper(), target, headers, xhost, xexec, rest)

    def _connect(self, conn, peer, target, xhost, xexec, rest):
        host, _, port_s = target.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            return self._refuse(conn, peer, "BAD_CONNECT_TARGET", 400)
        ip, why = self._target_ip(host, xhost)
        if why:
            return self._refuse(conn, peer, why, host=xhost, dest_port=port, execution_id=xexec)
        tid, now = str(uuid.uuid4()), self.clock()
        try:
            ok = self.rec.insert({"sensor": "egress_proxy", "kind": "tunnel_open", "observation_id": tid, "tunnel_id": tid,
                                  "observed_at": now, "peer": peer, "host": xhost, "dest_ip": ip, "dest_port": port,
                                  "execution_id": xexec})
        except DbError:                                  # unique execution id per tunnel (design §7.5)
            self.rec.alert("EXECUTION_ID_REUSE", {"execution_id": xexec}, now)
            return self._refuse(conn, peer, "EXECUTION_ID_REUSE", host=xhost, dest_ip=ip, dest_port=port)
        if not ok:                                       # fail closed: no evidence => no egress
            return self._refuse(conn, peer, "OBSERVER_CANNOT_RECORD", 503)
        with self._lock:
            self.open_tunnels[tid] = {"opened": now, "host": xhost, "dest_ip": ip, "execution_id": xexec}
        bin_, bout, reason, sni = 0, 0, "CLOSED", None
        up = None
        try:
            try:
                up = socket.create_connection((ip, port), timeout=5)
            except OSError:
                reason = "UPSTREAM_UNREACHABLE"
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            first = rest
            conn.settimeout(5)
            while len(first) < 5 or len(first) < 5 + int.from_bytes(first[3:5], "big"):
                d = conn.recv(16384)
                if not d:
                    break
                first += d
                if len(first) > 65536:
                    break
            sni = parse_sni(first)
            if xhost is not None and sni != xhost:
                reason = "SNI_MISMATCH"                  # incl. no SNI / not TLS on a tagged tunnel (fronting, ECH)
                self.rec.insert({"sensor": "egress_proxy", "kind": "refused", "observed_at": self.clock(), "peer": peer,
                                 "tunnel_id": tid, "host": xhost, "sni": sni, "dest_ip": ip, "dest_port": port,
                                 "execution_id": xexec, "reason": reason})
                self.rec.alert("EGRESS_REFUSED", {"reason": reason}, self.clock())
                return
            up.sendall(first)
            bout += len(first)
            bin_, bout2, reason = self._relay(conn, up, now)
            bout += bout2
        except OSError:
            reason = "IO_ERROR"
        finally:
            for s in (up, conn):
                try:
                    s and s.close()
                except OSError:
                    pass
            with self._lock:
                self.open_tunnels.pop(tid, None)
            self.rec.insert({"sensor": "egress_proxy", "kind": "tunnel_close", "observed_at": now, "closed_at": self.clock(),
                             "tunnel_id": tid, "peer": peer, "host": xhost, "sni": sni, "dest_ip": ip, "dest_port": port,
                             "execution_id": xexec, "bytes_in": bin_, "bytes_out": bout, "reason": reason})

    def _relay(self, a, b, opened: float) -> Tuple[int, int, str]:
        """Bidirectional copy until either side closes or T_tunnel expires. Returns (bytes up->client, client->up, why)."""
        import selectors
        sel = selectors.DefaultSelector()
        a.setblocking(False); b.setblocking(False)
        sel.register(a, selectors.EVENT_READ, b); sel.register(b, selectors.EVENT_READ, a)
        to_client = to_up = 0
        try:
            while True:
                left = opened + self.t_tunnel - self.clock()
                if left <= 0:
                    return to_client, to_up, "T_TUNNEL_EXPIRED"
                ev = sel.select(timeout=min(left, 1.0))
                for key, _ in ev:
                    try:
                        d = key.fileobj.recv(65536)
                    except BlockingIOError:
                        continue
                    if not d:
                        return to_client, to_up, "CLOSED"
                    key.data.setblocking(True)
                    key.data.sendall(d)
                    key.data.setblocking(False)
                    if key.fileobj is b:
                        to_client += len(d)
                    else:
                        to_up += len(d)
        finally:
            sel.close()

    def _http(self, conn, peer, method, target, headers, xhost, xexec, rest):
        from urllib.parse import urlsplit
        u = urlsplit(target)
        if u.scheme != "http" or not u.hostname:
            return self._refuse(conn, peer, "NOT_ABSOLUTE_HTTP", 400)
        ip, why = self._target_ip(u.hostname if ":" not in (u.hostname or "") else "[%s]" % u.hostname, xhost)
        port = u.port or 80
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        import hashlib
        if why:
            return self._refuse(conn, peer, why, host=xhost, dest_port=port, execution_id=xexec)
        now = self.clock()
        try:
            ok = self.rec.insert({"sensor": "egress_proxy", "kind": "http_request", "observed_at": now, "peer": peer,
                                  "host": xhost or headers.get("host", "")[:253], "dest_ip": ip, "dest_port": port,
                                  "execution_id": xexec, "method": method[:10],
                                  "path_sha256": hashlib.sha256(path.encode()).hexdigest()})
        except DbError:
            self.rec.alert("EXECUTION_ID_REUSE", {"execution_id": xexec}, now)
            return self._refuse(conn, peer, "EXECUTION_ID_REUSE", host=xhost, dest_ip=ip, dest_port=port)
        if not ok:                                       # fail closed: no evidence => no egress
            return self._refuse(conn, peer, "OBSERVER_CANNOT_RECORD", 503)
        fwd = {k: v for k, v in headers.items() if not k.startswith(("x-qyrix-", "proxy-")) and k not in ("connection", "keep-alive")}
        n = min(int(headers.get("content-length", "0") or 0), 1024 * 1024)
        body = rest
        conn.settimeout(10)
        while len(body) < n:
            d = conn.recv(65536)
            if not d:
                break
            body += d
        try:
            up = socket.create_connection((ip, port), timeout=5)
        except OSError:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        try:
            req = "%s %s HTTP/1.1\r\n" % (method, path) + "".join("%s: %s\r\n" % (k, v) for k, v in fwd.items()) + "Connection: close\r\n\r\n"
            up.sendall(req.encode("latin-1") + body[:n])
            up.settimeout(10)
            while True:
                d = up.recv(65536)
                if not d:
                    break
                conn.sendall(d)
        except OSError:
            pass
        finally:
            up.close()


class DnsForwarder:
    """UDP DNS forwarder: records every query (qname, qtype, peer) as E3, then relays to the upstream resolver."""

    def __init__(self, recorder: Recorder, host: str, port: int, upstream: Tuple[str, int], clock=time.time):
        self.rec, self.upstream, self.clock = recorder, upstream, clock
        fwd = self

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                fwd._handle(data, sock, self.client_address)

        class S(socketserver.ThreadingMixIn, socketserver.UDPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = S((host, port), H)
        self.host, self.port = self.server.server_address[:2]
        threading.Thread(target=self.server.serve_forever, name="observer-dns", daemon=True).start()

    @staticmethod
    def question(data: bytes) -> Optional[Tuple[str, int]]:
        try:
            if len(data) < 12 or int.from_bytes(data[4:6], "big") < 1:
                return None
            p, labels = 12, []
            while True:
                ln = data[p]
                if ln == 0:
                    p += 1
                    break
                if ln > 63:
                    return None
                labels.append(data[p + 1:p + 1 + ln].decode("ascii").lower())
                p += 1 + ln
            return ".".join(labels)[:253], int.from_bytes(data[p:p + 2], "big")
        except (IndexError, UnicodeDecodeError):
            return None

    def _handle(self, data, sock, addr):
        q = self.question(data)
        if q is None:
            self.rec.count("dns_malformed")
            return
        self.rec.insert({"sensor": "dns", "kind": "dns_query", "observed_at": self.clock(), "peer": addr[0],
                         "qname": q[0], "qtype": q[1]})
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(2)
        try:
            u.sendto(data, self.upstream)
            ans, _ = u.recvfrom(4096)
            sock.sendto(ans, addr)
        except OSError:
            self.rec.count("dns_upstream_error")
        finally:
            u.close()

    def close(self):
        self.server.shutdown(); self.server.server_close()


class Sink:
    """Coverage sink on the observer's EXTERNAL side: TCP ports + UDP 53. Records tokens it receives (sha256 only)."""

    def __init__(self, recorder: Recorder, host: str, tcp_ports: Iterable[int] = (80, 443, 853), udp_port: int = 53,
                 clock=time.time):
        import hashlib
        self.rec, self.clock, self.servers = recorder, clock, []
        sink = self

        def record(data: bytes, peer, port, proto):
            for m in TOKEN_RE.finditer(data[:4096]):
                sink.rec.insert({"sensor": "sink", "kind": "sink_hit", "observed_at": sink.clock(), "peer": peer,
                                 "dest_port": port, "method": proto,
                                 "token_sha256": hashlib.sha256(m.group(1)).hexdigest()})

        for port in tcp_ports:
            class T(socketserver.BaseRequestHandler):
                p = port

                def handle(self):
                    self.request.settimeout(3)
                    try:
                        data = self.request.recv(4096)
                    except OSError:
                        return
                    record(data, self.client_address[0], self.p, "tcp")
                    try:
                        self.request.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    except OSError:
                        pass

            class TS(socketserver.ThreadingMixIn, socketserver.TCPServer):
                daemon_threads = True
                allow_reuse_address = True
            self.servers.append(TS((host, port), T))

        class U(socketserver.BaseRequestHandler):
            def handle(self):
                record(self.request[0], self.client_address[0], udp_port, "udp")

        class US(socketserver.ThreadingMixIn, socketserver.UDPServer):
            daemon_threads = True
            allow_reuse_address = True
        if udp_port:
            self.servers.append(US((host, udp_port), U))
        for s in self.servers:
            threading.Thread(target=s.serve_forever, name="observer-sink", daemon=True).start()
        self.ports = [s.server_address[1] for s in self.servers]

    def close(self):
        for s in self.servers:
            s.shutdown(); s.server_close()


def new_token() -> str:
    return secrets.token_bytes(16).hex()
