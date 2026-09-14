#!/usr/bin/env bash
# Run a UDP port scan (different protocol)
# Usage: bash lab/scripts/run_udpscan.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] UDP scan of ${VICTIM_IP} common ports"
docker exec ids-attacker nmap -sU -p 53,123,161,500,514,1900 "${VICTIM_IP}"
