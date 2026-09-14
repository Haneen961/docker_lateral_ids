#!/usr/bin/env bash
# Run a targeted port scan (specific ports of interest)
# Usage: bash lab/scripts/run_specific_scan.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] Targeted scan of ${VICTIM_IP} (common attack ports)"
docker exec ids-attacker nmap -sS -p 21,22,23,25,80,443,3389,3306,5432,8080 "${VICTIM_IP}"
