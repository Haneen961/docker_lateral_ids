# Docker Lateral Movement IDS

Real-time detection + mitigation of **lateral movement** attacks (port scans, SSH brute-force) on a Docker bridge network. The system combines a **multi-rule threshold detector** with a **Random Forest** classifier over an 18-feature, dual-window flow representation, and automatically stops the offending container via the Docker SDK.


## Project layout

```
docker_lateral_ids/
├── README.md
├── requirements.txt
├── evaluate.py                  # Offline P/R/F1/FPR/latency report
├── src/                         # Detection runtime (the IDS daemon)
│   ├── capture.py               # Scapy AsyncSniffer on the docker bridge
│   ├── features.py              # 18-feature dual-window aggregator
│   ├── threshold_detector.py    # 5-rule threshold detector
│   ├── ml_detector.py           # Random Forest detector
│   ├── mitigation.py            # docker stop via Docker SDK
│   ├── alerts.py                # JSONL alert sink
│   └── main.py                  # Live IDS orchestrator
├── ml/                          # Datasets + training
│   ├── gen_offline_synth.py     # Realistic synthetic CSV (no Docker)
│   ├── generate_synthetic.py    # Capture real lab traffic + label it
│   ├── prepare_cicids.py        # CIC-IDS2017 → 18-feature CSV
│   └── train.py                 # Train the Random Forest
├── lab/                         # Attacker + victim containers
│   ├── docker-compose.yml
│   ├── attacker/Dockerfile      # nmap + hydra
│   ├── victim/Dockerfile        # sshd + nginx
│   └── scripts/                 # 17 attack + 1 benign scripts
├── data/                        # CSV datasets + per-dataset report_*.csv
└── models/                      # rf_model.pkl, rf_lab.pkl, rf_cic.pkl
```

---

## Install

```bash
sudo apt install -y python3-venv libpcap-dev docker.io docker-compose-plugin tcpdump
cd docker_lateral_ids
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

## Quick-start scenario

You want: **start the IDS → run an attack script → IDS detects in real time → malicious container is auto-stopped**.

### Step 1 — Build & start the lab

```bash
docker compose -f lab/docker-compose.yml up -d --build
docker ps --filter \"name=ids-\"
```

This creates a user-defined bridge `idsnet` (`172.30.0.0/16`) with two containers:

| Container       | Role     | Tools inside                          |
|-----------------|----------|---------------------------------------|
| `ids-attacker`  | attacker | `nmap`, `hydra`, `curl`, `ping`       |
| `ids-victim`    | victim   | `sshd` (22), `nginx` (80)             |

Locate the Linux bridge interface for the network:

```bash
docker network inspect idsnet -f '{{.Id}}' | cut -c1-12
ip -br link | grep br-          # e.g. br-4f9c8a1d2e6b
```

Use that `br-XXXX` as `--iface` below.

### Step 2 — Train the Random Forest

You can train *now* with synthetic data (fast, ~10 s) and retrain later on real lab capture or CIC-IDS2017.

```bash
# Synthetic
python ml/gen_offline_synth.py --out data/flows.csv --rows 6000
python ml/train.py --data data/flows.csv --out models/rf_model.pkl
```

### Step 3 — Start the IDS daemon

In **terminal A**:

```bash
sudo .venv/bin/python -m src.main \
    --iface br-XXXX \
    --mode hybrid \
    --model models/rf_model.pkl \
    --window 120 \
    --tick 1 \
    --alerts-log data/alerts.jsonl \
    --whitelist ids-attacker ids-victim     # remove this when you want auto-stop
```

The daemon sniffs every packet on the bridge, recomputes the 18-feature vector once per `--tick` second over the long sliding window (120 s) plus a short 5 s window, and runs both detectors in parallel. End-to-end latency from first malicious packet to alert is typically **< 1.5 s**.

### Step 4 — In another terminal, run an attack script

**Terminal B**:

```bash
bash lab/scripts/run_portscan.sh        # nmap -sS -T4 against the victim
bash lab/scripts/run_ssh_brute.sh       # hydra ssh against the victim
bash lab/scripts/run_stealth_scan.sh    # nmap -T1 --scan-delay 1s
bash lab/scripts/benign_traffic.sh      # curl + ping loop (sanity, no FPs)
```

There are 17 attack scripts in `lab/scripts/` covering aggressive, stealth, fragmented, decoy, version, UDP, idle, chained and distributed variants, plus three SSH brute-force flavours.

### Step 5 — Watch the IDS detect it

In terminal A you'll see lines like:

```text
ALERT {\"ts_iso\":\"…\",\"src_ip\":\"172.30.0.3\",\"detections\":[
  {\"engine\":\"threshold\",\"rule\":\"AGGRESSIVE_SCAN\",\"score\":1500,\"detail\":\"1500 TCP ports in 5 s\"},
  {\"engine\":\"ml\",\"label\":\"PortScan\",\"proba\":0.998}
],\"mitigation\":{\"stopped_container\":null,\"dry_run\":false}}
```

Every alert is also appended to `data/alerts.jsonl`. To actually **auto-stop** the attacker, remove `--whitelist ids-attacker` in step 3 — the attacker container will be `docker stop`ped within ~1 s of the scan starting.

### Step 6 — Evaluate offline

```bash
python evaluate.py --data data/flows.csv --model models/rf_model.pkl --out data/report.csv
cat data/report.csv
```

---

## Datasets

| Source        | Script                                                         | When to use                                                    |
|---------------|----------------------------------------------------------------|----------------------------------------------------------------|
| Synthetic     | `ml/gen_offline_synth.py`                                      | Quick start, no Docker; 8 evasion variants + label noise        |
| Real lab      | `sudo python ml/generate_synthetic.py --iface br-XXXX ...`     | Most faithful: real packets captured while the 17 scripts run   |
| CIC-IDS2017   | `python ml/prepare_cicids.py --src /path/to/CIC-IDS2017/ ...`  | Public benchmark — PortScan + SSH-Patator subsets               |

You can also concatenate them:

```bash
python -c \"import pandas as pd; \
  pd.concat([pd.read_csv('data/flows.csv'), pd.read_csv('data/cic_subset.csv')]).to_csv('data/combined.csv', index=False)\"
python ml/train.py --data data/combined.csv --out models/rf_combined.pkl
```

---

## Results

Offline scores on the three datasets (reproduced from `data/report*.csv`):

| Dataset       | Detector  | Precision | Recall | F1     | FPR     | ms/sample |
|---------------|-----------|-----------|--------|--------|---------|-----------|
| Synthetic     | Threshold | 0.9799    | 0.8241 | 0.8953 | 0.0187  | 0.256     |
| Synthetic     | **ML**    | **0.9955**| 0.9631 | 0.9791 | 0.0048  | 0.031     |
| Lab           | Threshold | 0.3675    | 0.9558 | 0.5309 | 0.6251  | 0.264     |
| Lab           | **ML**    | **1.0000**| 0.9988 | 0.9994 | 0.0000  | 0.026     |
| CIC-IDS2017   | Threshold | 0.0000    | 0.0000 | 0.0000 | 0.0000  | 0.234     |
| CIC-IDS2017   | **ML**    | **0.8741**| 0.9964 | 0.9313 | 0.1182  | 0.015     |

The threshold engine is unable to fire on CIC-IDS2017 because each CIC row is a single pre-aggregated flow, so the per-source diversity features (`unique_dst_ports`, `short_unique_ports`) are always `≤ 1`. The Random Forest exploits the flag-count and packet-size features and still reaches `F1 = 0.93`.

See `report/report.pdf` for the full discussion.

---

## How real-time works (architecture summary)

```
Scapy AsyncSniffer (background thread)  --> bounded queue
        │
        ▼
Main loop drains queue + ticks every 1 s
        │
        ▼
Dual sliding-window aggregator (long 120 s / short 5 s) → 18 features
        │
        ▼
ThresholdDetector  ─┐
                    ├─► detections list (OR-fusion)
MLDetector (RF)    ─┘
        │
        ▼
Mitigator → docker.containers.get(<from src IP>).stop()
        │
        ▼
AlertSink → data/alerts.jsonl
```

Tuning knobs in `src/main.py`:

| Flag                       | Meaning                                                                   |
|----------------------------|---------------------------------------------------------------------------|
| `--window 120`             | Long sliding-window length in seconds                                     |
| `--tick 1`                 | Detector evaluation cadence (smaller = lower latency, more CPU)            |
| `--direction incoming`     | Attribute features to attackers via destinations (recommended)            |
| `--port-scan-threshold 20` | Aggressive-scan short-window port count                                   |
| `--ssh-brute-threshold 10` | SSH brute-force SYN count                                                 |
| `--ml-proba 0.7`           | RF probability cut-off                                                    |
| `--mute-after-stop 300`    | Suppress alerts for this source for N seconds after a container is stopped|
| `--dry-run`                | Log the intended mitigation but do not actually stop the container        |

Tuning knobs in the offline evaluator (`evaluate.py`) mirror the same thresholds.

---

## Troubleshooting

| Symptom                                | Fix                                                                 |
|----------------------------------------|---------------------------------------------------------------------|
| `Operation not permitted` on sniff     | Run with `sudo` (raw socket needs `CAP_NET_RAW`)                    |
| No alerts on attack                    | Wrong `--iface`; verify with `tcpdump -i br-XXXX -nn` while running |
| `ModuleNotFoundError: scapy`           | Activate the venv and `pip install -r requirements.txt`             |
| Attacker stopped on first scan         | Add `--whitelist ids-attacker` (intended for testing)               |
| Empty `IP→container` map in mitigator  | Ensure the user can talk to the Docker socket (`docker` group)      |

---

## Reproducing the report numbers

```bash
# Synthetic
python ml/gen_offline_synth.py --out data/flows.csv --rows 6000
python ml/train.py --data data/flows.csv --out models/rf_model.pkl
python evaluate.py --data data/flows.csv --model models/rf_model.pkl --out data/report.csv

# Lab (run after the docker compose lab is up)
sudo python ml/generate_synthetic.py --iface br-XXXX --out data/lab_flows.csv \
     --phase \"BENIGN:lab/scripts/benign_traffic.sh:60\" \
     --phase \"PortScan:lab/scripts/run_portscan.sh:30\" \
     --phase \"PortScan:lab/scripts/run_stealth_scan.sh:90\" \
     --phase \"PortScan:lab/scripts/run_random_scan.sh:30\" \
     --phase \"PortScan:lab/scripts/run_decoy_scan.sh:30\" \
     --phase \"PortScan:lab/scripts/run_fragmented_scan.sh:60\" \
     --phase \"PortScan:lab/scripts/run_mass_scan.sh:20\" \
     --phase \"PortScan:lab/scripts/run_versionscan.sh:30\" \
     --phase \"PortScan:lab/scripts/run_udp_scan.sh:30\" \
     --phase \"SSH-Patator:lab/scripts/run_ssh_brute.sh:60\" \
     --phase \"SSH-Patator:lab/scripts/run_slow_brute.sh:120\"
python ml/train.py    --data data/lab_flows.csv --out models/rf_lab.pkl
python evaluate.py --data data/lab_flows.csv --model models/rf_lab.pkl --out data/report_lab.csv

# CIC-IDS2017
python ml/prepare_cicids.py --src /path/to/CIC-IDS2017/ --out data/cic_subset.csv
python ml/train.py    --data data/cic_subset.csv --out models/rf_cic.pkl
python evaluate.py --data data/cic_subset.csv --model models/rf_cic.pkl --out data/report_cic.csv
```

---
