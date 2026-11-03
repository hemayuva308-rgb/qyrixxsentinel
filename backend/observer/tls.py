"""Observer transport security (audit F2): mutual TLS.

Server: OBSERVER_TLS_CERT_FILE + OBSERVER_TLS_KEY_FILE + OBSERVER_TLS_CLIENT_CA_FILE => TLS with REQUIRED client
certificates (mTLS). A non-loopback bind without all three is refused at start-up (fail closed). Plain HTTP is allowed
only on loopback (tests / local development).

Operator tooling (development / demo PKI; production may use its own CA):
    python -m observer.tls ca     --out DIR
    python -m observer.tls issue  --ca DIR --name observer --san observer --san 127.0.0.1 --server --out DIR
    python -m observer.tls issue  --ca DIR --name backend --client --out DIR
Private keys are written with mode 0600 and never printed."""
import argparse
import datetime
import ipaddress
import os
import ssl
import sys
from typing import Dict, List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def server_settings(env, host: str) -> Dict:
    """uvicorn keyword arguments for the observer listener, or SystemExit (fail closed)."""
    cert, key, ca = (env.get("OBSERVER_TLS_CERT_FILE"), env.get("OBSERVER_TLS_KEY_FILE"), env.get("OBSERVER_TLS_CLIENT_CA_FILE"))
    if not any((cert, key, ca)):
        if not loopback(host):
            raise SystemExit("refusing to serve the observer on %s without mTLS (set OBSERVER_TLS_CERT_FILE, "
                             "OBSERVER_TLS_KEY_FILE and OBSERVER_TLS_CLIENT_CA_FILE)" % host)
        return {}
    if not all((cert, key, ca)):
        raise SystemExit("incomplete TLS configuration: certificate, key AND client CA are all required (mTLS)")
    return {"ssl_certfile": cert, "ssl_keyfile": key, "ssl_ca_certs": ca, "ssl_cert_reqs": ssl.CERT_REQUIRED}


def _write_key(path: str, k) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def make_ca(out: str, name: str = "Qyrix Observer CA", days: int = 365) -> None:
    os.makedirs(out, exist_ok=True)
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
         .not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
         .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .sign(k, hashes.SHA256()))
    _write_key(os.path.join(out, "ca.key"), k)
    open(os.path.join(out, "ca.crt"), "wb").write(c.public_bytes(serialization.Encoding.PEM))


def issue(ca_dir: str, name: str, sans: List[str], server: bool, out: str, days: int = 90) -> None:
    os.makedirs(out, exist_ok=True)
    ca_key = serialization.load_pem_private_key(open(os.path.join(ca_dir, "ca.key"), "rb").read(), None)
    ca_crt = x509.load_pem_x509_certificate(open(os.path.join(ca_dir, "ca.crt"), "rb").read())
    k = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    alt = []
    for s in sans:
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            alt.append(x509.DNSName(s))
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
         .issuer_name(ca_crt.subject).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
         .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]),
                        critical=False))
    if alt:
        b = b.add_extension(x509.SubjectAlternativeName(alt), critical=False)
    c = b.sign(ca_key, hashes.SHA256())
    _write_key(os.path.join(out, name + ".key"), k)
    open(os.path.join(out, name + ".crt"), "wb").write(c.public_bytes(serialization.Encoding.PEM))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("ca"); c.add_argument("--out", required=True)
    i = sub.add_parser("issue")
    i.add_argument("--ca", required=True); i.add_argument("--name", required=True); i.add_argument("--out", required=True)
    i.add_argument("--san", action="append", default=[])
    g = i.add_mutually_exclusive_group(required=True); g.add_argument("--server", action="store_true"); g.add_argument("--client", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "ca":
        make_ca(a.out)
    else:
        issue(a.ca, a.name, a.san, a.server, a.out)
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
