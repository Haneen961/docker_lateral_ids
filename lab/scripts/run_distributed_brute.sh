#!/usr/bin/env bash
# Run distributed SSH brute from multiple source ports
# Usage: bash lab/scripts/run_distributed_brute.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] Distributed SSH brute against ${VICTIM_IP}"
for i in {1..5}; do
    docker exec ids-attacker ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -p $((2200+$i)) root@${VICTIM_IP} exit 2>/dev/null &
done
wait
