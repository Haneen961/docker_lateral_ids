#!/usr/bin/env bash
# Run a port scan with decoy IPs (evasion technique)
# Usage: bash lab/scripts/run_decoy_scan.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] Decoy scan of ${VICTIM_IP} (spoofed source IPs)"
docker exec ids-attacker nmap -sS -D RND:5,ME -p 1-1000 "${VICTIM_IP}"
