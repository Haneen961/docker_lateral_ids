#!/usr/bin/env bash
# UDP port scan (different protocol)
# Usage: bash lab/scripts/run_udp_scan.sh

set -euo pipefail

VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"

echo "[+] UDP port scan against ${VICTIM_IP}"
echo "Note: UDP scanning is slow and may take time"

# Common UDP ports
UDP_PORTS="53,123,161,500,514,1900,5353"

echo "[*] Scanning UDP ports: $UDP_PORTS"
docker exec ids-attacker nmap -sU -p $UDP_PORTS "$VICTIM_IP"

echo "[+] UDP scan complete"
