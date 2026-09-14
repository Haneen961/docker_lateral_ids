#!/usr/bin/env bash
# Run a port scan with fragmented packets (evasion technique)
# Usage: bash lab/scripts/run_fragmented_scan.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] Fragmented packet scan of ${VICTIM_IP} ports 1-1000"
docker exec ids-attacker nmap -sS -f -p 1-1000 "${VICTIM_IP}"
