#!/bin/sh
# Host firewall for the C5 overlay (design §7.1): traffic entering from a backend-side bridge may only stay on that
# bridge. Evaluated in DOCKER-USER, i.e. BEFORE Docker's own rules; IPv4 and IPv6. Idempotent.
#   sudo ops/observer/docker-user.sh apply | check | undo
set -eu
BRIDGES="${QYRIX_BACKEND_BRIDGES:-qyrix-int qyrix-ingest qyrix-egin}"
cmd="${1:-check}"
for ipt in iptables ip6tables; do
  $ipt -N DOCKER-USER 2>/dev/null || true
  for br in $BRIDGES; do
    case "$cmd" in
      apply)
        $ipt -C DOCKER-USER -i "$br" ! -o "$br" -m comment --comment qyrix-c5 -j DROP 2>/dev/null \
          || $ipt -I DOCKER-USER 1 -i "$br" ! -o "$br" -m comment --comment qyrix-c5 -j DROP ;;
      undo)
        while $ipt -C DOCKER-USER -i "$br" ! -o "$br" -m comment --comment qyrix-c5 -j DROP 2>/dev/null; do
          $ipt -D DOCKER-USER -i "$br" ! -o "$br" -m comment --comment qyrix-c5 -j DROP
        done ;;
      check)
        $ipt -C DOCKER-USER -i "$br" ! -o "$br" -m comment --comment qyrix-c5 -j DROP \
          || { echo "missing: $ipt DOCKER-USER rule for $br"; exit 1; } ;;
      *) echo "usage: $0 apply|check|undo"; exit 2 ;;
    esac
  done
done
echo "DOCKER-USER $cmd: ok ($BRIDGES)"
