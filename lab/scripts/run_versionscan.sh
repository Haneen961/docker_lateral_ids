#!/usr/bin/env bash
# Run a service version detection scan (reconnaissance)
# Usage: bash lab/scripts/run_versionscan.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] Service version scan of ${VICTIM_IP} open ports"
docker exec ids-attacker nmap -sV -p 22,80,443,3306 "${VICTIM_IP}"
