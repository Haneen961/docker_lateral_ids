#!/usr/bin/env bash
# Run an idle/zombie scan (advanced evasion)
# Usage: bash lab/scripts/run_idle_scan.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] Idle scan of ${VICTIM_IP} (requires zombie host)"
echo "Note: This scan requires a zombie host with predictable IP ID"
docker exec ids-attacker nmap -sI www.google.com -p 1-1000 "${VICTIM_IP}"
