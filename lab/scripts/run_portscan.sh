#!/usr/bin/env bash
# Run a TCP SYN port scan from the attacker against the victim.
# Usage: bash lab/scripts/run_portscan.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] Scanning ${VICTIM_IP} ports 1-2000"
docker exec ids-attacker nmap -sS -T4 -p 1-2000 "${VICTIM_IP}"

