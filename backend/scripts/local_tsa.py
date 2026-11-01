"""LOCAL TEST TSA for rehearsal only - NOT an external, independent timestamp authority.
  cd backend && python scripts/local_tsa.py           # prints QYRIX_TSA_URL and QYRIX_TSA_CA_FILE to export
Runs a real RFC 3161 TSA (openssl ts -reply) with a throwaway CA so the anchoring flow can be exercised end to end.
A PASS obtained with it proves the MECHANISM only. Never present it as external anchoring: the tsa_url shown in the
UI and in every anchor record is the 127.0.0.1 address of this process. For real anchoring use a public RFC 3161 TSA
(QYRIX_TSA_URL + its CA certificate in QYRIX_TSA_CA_FILE) and the docker-compose.egress.yml override."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.tsa_local import LocalTSA

t = LocalTSA("QYRIX LOCAL TEST TSA - NOT EXTERNAL")
print("LOCAL TEST TSA running (Ctrl+C to stop). In the backend's environment set:")
print("  export QYRIX_TSA_URL=%s" % t.url)
print("  export QYRIX_TSA_CA_FILE=%s" % t.ca_file)
try:
    while True:
        time.sleep(3600)
except KeyboardInterrupt:
    t.close()
