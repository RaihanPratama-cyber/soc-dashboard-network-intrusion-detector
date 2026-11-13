# SOC Dashboard — Network Intrusion Detector

A Flask web app that detects common lab-network attacks — **MAC flooding,
DHCP starvation, ARP poisoning, and port scan** — and presents them in a
real-time-style SOC dashboard with alerts, logs, and graphs.

Built as a portfolio project by **Raihan Pratama** (Politeknik Caltex Riau,
3 TRK A), based on the Workshop Keamanan Jaringan (WKJ) labs.

## What it does

| Page | What you see |
| --- | --- |
| **Overview** (`/`) | Counters (packets, alerts, severity), packets-per-minute chart, latest alerts, packets per protocol |
| **Alerts** (`/alerts`) | Every alert with its rule, severity, source, time window, and the evidence that triggered it |
| **Logs** (`/logs`) | The full packet table with the simulation label of each row |

API endpoints:

| Endpoint | Description |
| --- | --- |
| `GET /health` | Health check — `{"status": "ok"}` |
| `GET /api/summary` | Counters (packets, alerts by severity, protocols) |
| `GET /api/alerts` | All alerts as JSON |
| `GET /api/logs` | All sample rows as JSON |
| `POST /api/check` | Check your own sample: send `{"rows": [...]}` or `{"csv": "..."}` and get back alerts |

## How detection works

Rule-based, explainable detection in `detector.py` — every alert lists the
rule and the exact observation that triggered it:

| Rule | Attack | Signal |
| --- | --- | --- |
| `MAC-FLOOD-01` | MAC flooding | ≥ 50 unique source MACs in 54-byte frames on one switch port within 60 s (macof sends 54-byte frames with random source MACs until the switch CAM table overflows) |
| `DHCP-STARVE-01` | DHCP starvation | ≥ 100 DHCP DISCOVER packets within 60 s, from many MACs with distinct Transaction IDs (yersinia exhausts the DHCP pool so real clients get no address) |
| `ARP-POISON-01` | ARP poisoning | One IP claimed by ≥ 2 MACs (Wireshark: "Duplicate IP address detected") — the attacker answers ARP for the victim/gateway IP with its own MAC |
| `PORT-SCAN-01` | Port scan | One source IP contacting ≥ 15 distinct destination ports within 60 s |

Thresholds are constants at the top of `detector.py` — adjust them for your
own lab.

## Real lab numbers behind the demo

The sample dataset (`data/sample_attacks.csv`, 276 rows) is a **simulated,
reduced excerpt** modelled on real observations from Raihan's WKJ labs:

- **MAC flooding** — `macof`, 54-byte frames.
- **DHCP starvation** — `yersinia`, **3,306,566 DISCOVER packets** in the real
  lab, Transaction ID `0x643c9869`, server port 68. The sample keeps the first
  120 DISCOVERs (one per Transaction ID) so the demo stays small.
- **ARP poisoning** — Cain & Abel and `hping3`, hosts **10.10.1.11 vs
  10.10.1.13**, "Duplicate IP address detected" in Wireshark.
- **Port scan** — one host probing 20 ports on 10.10.1.13.

Regenerate the dataset any time with:

```bash
python generate_sample_data.py
```

## How to run

```bash
# 1. Create a virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Run the tests
pytest -q

# 3. Start the dashboard
python app.py
```

Open <http://127.0.0.1:5000> in your browser.

## Try the check API

```bash
curl -s http://127.0.0.1:5000/health

curl -s -X POST http://127.0.0.1:5000/api/check \
  -H "Content-Type: application/json" \
  -d '{"rows": [
    {"timestamp": "2026-11-12T10:00:01", "src_mac": "00:1a:2b:3c:4d:5e",
     "dst_mac": "ff:ff:ff:ff:ff:ff", "src_ip": "10.10.1.11",
     "dst_ip": "10.10.1.13", "src_port": 0, "dst_port": 0,
     "protocol": "ARP", "frame_len": 42, "info": "ARP reply"},
    {"timestamp": "2026-11-12T10:00:02", "src_mac": "aa:bb:cc:11:22:33",
     "dst_mac": "ff:ff:ff:ff:ff:ff", "src_ip": "10.10.1.11",
     "dst_ip": "10.10.1.13", "src_port": 0, "dst_port": 0,
     "protocol": "ARP", "frame_len": 42, "info": "ARP reply"}
  ]}'
```

Expected: one `ARP-POISON-01` alert (critical) — IP 10.10.1.11 claimed by two
MACs.

## Using your own pcap

Export from Wireshark (`File → Export Packet Dissections → as CSV`) or parse
with `tshark`/`scapy` into the same columns as `data/sample_attacks.csv`:

```
timestamp,src_mac,dst_mac,src_ip,dst_ip,src_port,dst_port,protocol,frame_len,info
```

Then `POST` the rows to `/api/check`, or replace `data/sample_attacks.csv`
and reload the dashboard.

## Screenshots (what the pages look like)

- **Overview** — dark SOC theme: six counter cards (276 packets, 4 alerts,
  2 critical, 1 high), a bar chart of packets per minute with a red spike at
  10:02–10:05 (the attack window), a table of the latest alerts, and a
  per-protocol breakdown.
- **Alerts** — four alert cards, one per attack, each with severity badge,
  rule code, source, time window, and a plain-language evidence paragraph.
- **Logs** — a 276-row packet table, colour-tagged by simulation label
  (`mac_flooding`, `dhcp_starvation`, `arp_poisoning`, `port_scan`, `normal`).

## Honest limits

- **Simulated data.** The bundled dataset is generated, not a real capture.
  Real captures will need threshold tuning — a busy network can trip
  `PORT-SCAN-01`, and a legitimate DHCP relay can look like starvation.
- **Educational / defensive use only.** This is a lab portfolio project, not
  a production IDS. It does not capture live traffic, does not block anything,
  and must not be used to attack networks you do not own or have permission
  to test.
- **Simple rules, no ML.** Thresholds are fixed; there is no baseline
  learning, no encrypted-traffic inspection, and no correlation across days.

## Project structure

```
├── app.py                    # Flask app: pages + API
├── detector.py               # Rule-based detection (all four attacks)
├── generate_sample_data.py   # Regenerates data/sample_attacks.csv
├── data/sample_attacks.csv   # 276-row simulated dataset
├── templates/                # Overview / Alerts / Logs pages
├── static/css/style.css      # Dark SOC theme
├── static/js/dashboard.js    # Packets-per-minute bar chart (no CDN)
├── tests/test_detector.py    # 20 unit + API tests
├── requirements.txt
├── .gitignore
└── LICENSE                   # MIT
```

## License

MIT — see [LICENSE](LICENSE).
