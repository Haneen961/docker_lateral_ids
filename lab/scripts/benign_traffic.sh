#!/usr/bin/env bash
# Generate benign cross-container traffic for ~60 seconds.
set -euo pipefail
VICTIM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-victim)"
echo "[+] Benign traffic loop towards ${VICTIM_IP} (60s)"
docker exec ids-attacker sh -c "
for i in \$(seq 1 60); do
  curl -s ${VICTIM_IP}:80 >/dev/null
  ping -c 1 ${VICTIM_IP} >/dev/null
  sleep 1
done
"

