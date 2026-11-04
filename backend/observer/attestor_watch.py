"""Event-driven re-attestation (C5 hardening). Runs as ROOT ON THE DOCKER HOST next to the attestor:

    python3 -m observer.attestor_watch --config /etc/qyrix/attestor.json

- attests once at start (a restarted watcher never relies on an older attestation);
- follows `docker events` and re-attests (debounced) when the backend container starts, restarts, stops, dies, is
  killed, updated, renamed or destroyed, or when ANY container is connected to / disconnected from a network the
  backend uses or the observer's `egress` network;
- a stopped / missing backend yields a signed FAILED attestation (observer.attestor.absent), which revokes coverage
  immediately - the latest attestation always decides, so an older success is never reused after a failed check;
- if `docker events` ends (daemon restart), the watcher exits non-zero; systemd restarts it (Restart=always).
Periodic attestation is the systemd timer (qyrix-attestor.timer); this watcher closes the gap between ticks."""
import argparse
import json
import subprocess  # nosec B404 - fixed docker / python argv, no shell
import sys
import threading
import time

CONTAINER_ACTIONS = {"start", "restart", "stop", "die", "kill", "oom", "pause", "unpause", "update", "rename", "destroy",
                     "create"}
NETWORK_ACTIONS = {"connect", "disconnect", "create", "destroy"}


def relevant(ev: dict, project: str, service: str, networks) -> bool:
    """Pure: does this docker event change what the last attestation proved?"""
    t, action = ev.get("Type"), str(ev.get("Action", "")).split(":")[0]
    attrs = (ev.get("Actor") or {}).get("Attributes") or {}
    if t == "container" and action in CONTAINER_ACTIONS:
        return attrs.get("com.docker.compose.project") == project and attrs.get("com.docker.compose.service") == service
    if t == "network" and action in NETWORK_ACTIONS:
        return attrs.get("name") in networks
    return False


class Watcher:
    def __init__(self, config: str, project: str, service: str, networks, debounce: float = 2.0, attest=None):
        self.config, self.project, self.service, self.networks, self.debounce = config, project, service, set(networks), debounce
        self._attest = attest or self._run_attestor
        self._timer = None
        self._lock = threading.Lock()
        self.runs = []

    def _run_attestor(self) -> int:
        r = subprocess.run([sys.executable, "-m", "observer.attestor", "--config", self.config],   # nosec B603
                           capture_output=True, text=True, timeout=120)
        return r.returncode

    def attest_now(self, why: str) -> None:
        code = self._attest()
        self.runs.append({"at": time.time(), "why": why, "exit": code})
        print(json.dumps({"attestation": why, "valid": code == 0}), flush=True)

    def trigger(self, why: str) -> None:
        with self._lock:                                  # debounce bursts (compose recreate = many events)
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self.debounce, self.attest_now, args=(why,))
            self._timer.daemon = True
            self._timer.start()

    def handle(self, line: str) -> None:
        try:
            ev = json.loads(line)
        except ValueError:
            return
        if relevant(ev, self.project, self.service, self.networks):
            self.trigger("%s:%s" % (ev.get("Type"), ev.get("Action")))

    def follow(self) -> int:
        self.attest_now("watcher_start")
        p = subprocess.Popen(["docker", "events", "--format", "{{json .}}", "--filter", "type=container",   # nosec B603
                              "--filter", "type=network"], stdout=subprocess.PIPE, text=True)
        for line in p.stdout:
            self.handle(line)
        return 1                                          # event stream ended: let systemd restart us


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True)
    a = ap.parse_args(argv)
    cfg = json.load(open(a.config))
    nets = set(cfg["networks"].split(",")) | {cfg.get("egress-network", "%s_egress" % cfg["compose-project"])}
    return Watcher(a.config, cfg["compose-project"], cfg.get("compose-service", "backend"), nets).follow()


if __name__ == "__main__":
    sys.exit(main())
