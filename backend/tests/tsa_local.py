"""A real, local RFC 3161 Time-Stamp Authority for tests (and for local rehearsal via scripts/local_tsa.py).

It creates its own throwaway CA and a TSA signing certificate (extendedKeyUsage = critical, timeStamping) and answers
application/timestamp-query POSTs with `openssl ts -reply`. Tokens are genuinely signed and verifiable with openssl.
It is NOT an independent third party: a PASS obtained against it proves the mechanism, not external anchoring.
"""
import os, subprocess, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CNF = """
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = {cn}
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ v3_tsa ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,nonRepudiation
extendedKeyUsage = critical,timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
dir = {dir}
serial = $dir/serial
crypto_device = builtin
signer_cert = $dir/tsa.crt
certs = $dir/ca.crt
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.1
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""


def _ssl(*a, cwd=None):
    subprocess.run(["openssl", *a], check=True, capture_output=True, cwd=cwd)


class LocalTSA:
    def __init__(self, name="QYRIX LOCAL TEST TSA"):
        self.dir = tempfile.mkdtemp(prefix="qyrix-localtsa-")
        d = self.dir
        open(os.path.join(d, "ca.cnf"), "w").write(CNF.format(cn=name + " ROOT CA", dir=d))
        open(os.path.join(d, "tsa.cnf"), "w").write(CNF.format(cn=name, dir=d))
        open(os.path.join(d, "serial"), "w").write("01\n")
        _ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-days", "2",
             "-config", "ca.cnf", "-extensions", "v3_ca", cwd=d)
        _ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "tsa.key", "-out", "tsa.csr", "-config", "tsa.cnf", cwd=d)
        _ssl("x509", "-req", "-in", "tsa.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-out", "tsa.crt",
             "-days", "2", "-extfile", "tsa.cnf", "-extensions", "v3_tsa", cwd=d)
        self.ca_file = os.path.join(d, "ca.crt")
        self.fail_mode = None          # None | "http500" | "garbage" | "hang"
        tsa = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if tsa.fail_mode == "http500":
                    self.send_response(500); self.end_headers(); return
                if tsa.fail_mode == "garbage":
                    out = b"not a timestamp response"
                else:
                    with tempfile.TemporaryDirectory() as t:
                        q, r = os.path.join(t, "q.tsq"), os.path.join(t, "r.tsr")
                        open(q, "wb").write(body)
                        p = subprocess.run(["openssl", "ts", "-reply", "-config", os.path.join(d, "tsa.cnf"), "-queryfile", q,
                                            "-inkey", os.path.join(d, "tsa.key"), "-signer", os.path.join(d, "tsa.crt"), "-out", r],
                                           capture_output=True)
                        out = open(r, "rb").read() if p.returncode == 0 else b""
                self.send_response(200 if out else 400)
                self.send_header("Content-Type", "application/timestamp-reply"); self.send_header("Content-Length", str(len(out)))
                self.end_headers(); self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d/tsr" % self.srv.server_port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
