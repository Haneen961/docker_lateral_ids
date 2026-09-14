#!/usr/bin/env bash
# Run a port scan in random order (evasion technique)
# Usage: bash lab/scripts/run_random_scan.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
RANDOM_PORTS="$(shuf -i 1-2000 -n 500 | tr '\n' ',')"
echo "[+] Random order scan of ${VICTIM_IP} (500 random ports)"
docker exec ids-attacker nmap -sS -T4 -p "${RANDOM_PORTS}" "${VICTIM_IP}"
