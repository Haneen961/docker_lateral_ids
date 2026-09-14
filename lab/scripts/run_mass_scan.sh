#!/usr/bin/env bash
# Run a very fast mass port scan (aggressive)
# Usage: bash lab/scripts/run_mass_scan.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] Mass scan of ${VICTIM_IP} ports 1-5000"
docker exec ids-attacker nmap -sS -T5 -p 1-5000 --min-rate 1000 "${VICTIM_IP}"
