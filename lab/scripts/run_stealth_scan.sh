#!/usr/bin/env bash
# Run a slow TCP SYN port scan (evasion technique)
# Usage: bash lab/scripts/run_stealth_scan.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] Slow stealth scan of ${VICTIM_IP} ports 1-500"
docker exec ids-attacker nmap -sS -T1 -p 1-500 --scan-delay 1s "${VICTIM_IP}"
