"""
SOC Dashboard — Network Intrusion Detector (detector module).

Rule-based detection over parsed network log rows. Each row is a dict with
at least these keys (strings unless noted):

    timestamp   ISO-8601 string, e.g. "2026-11-12T10:00:01"
    src_mac     source MAC address
    dst_mac     destination MAC address
    src_ip      source IPv4 address
    dst_ip      destination IPv4 address
    src_port    source port (int or str)
    dst_port    destination port (int or str)
    protocol    e.g. "ARP", "DHCP", "TCP", "UDP", "ICMP"
    frame_len   frame length in bytes (int or str)
    info        free-text info field, e.g. "DHCP Discover - Transaction ID 0x643c9869"

Every alert explains itself: ``rule``, ``signal`` and ``evidence`` describe
exactly which observation triggered it, so an analyst can verify it by hand.
This is a teaching / lab detector — it works on labelled or simulated data,
not a production IDS.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Tunable thresholds (lab-scale defaults)
# ---------------------------------------------------------------------------
MAC_FLOOD_UNIQUE_MACS = 50      # unique src MACs from one port in the window
MAC_FLOOD_WINDOW = timedelta(seconds=60)
MAC_FLOOD_FRAME_LEN = 54        # macof generates 54-byte frames

DHCP_STARVATION_DISCOVERS = 100  # DISCOVER packets in the window
DHCP_STARVATION_WINDOW = timedelta(seconds=60)
DHCP_SERVER_PORT = 68

ARP_POISON_MIN_MACS = 2         # distinct MACs claiming the same IP
PORT_SCAN_MIN_PORTS = 15        # distinct dst ports from one src IP
PORT_SCAN_WINDOW = timedelta(seconds=60)


def _parse_ts(value):
    """Parse an ISO-8601 timestamp; return None when unparsable."""
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _norm_mac(mac):
    return str(mac or "").strip().lower()


def _norm_ip(ip):
    return str(ip or "").strip()


def _norm_port(port):
    try:
        return int(port)
    except (TypeError, ValueError):
        return None


def _norm_len(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_dhcp_discover(row):
    info = str(row.get("info", "")).lower()
    proto = str(row.get("protocol", "")).upper()
    return ("dhcp" in proto or "dhcp" in info) and "discover" in info


def _alert(alert_id, rule, title, severity, src, evidence, first_seen, last_seen):
    return {
        "id": alert_id,
        "rule": rule,
        "title": title,
        "severity": severity,          # low | medium | high | critical
        "source": src,
        "evidence": evidence,         # human-readable explanation
        "first_seen": first_seen.isoformat() if first_seen else None,
        "last_seen": last_seen.isoformat() if last_seen else None,
    }


def detect_mac_flooding(rows):
    """Many unique source MACs arriving on one switch port in a short window.

    macof floods a switch with forged 54-byte Ethernet frames, each carrying
    a random source MAC, until the CAM table overflows and the switch starts
    broadcasting traffic like a hub.
    """
    alerts = []
    # Group frames by (switch port, time window). The sample data carries the
    # ingress port in "port"; without it, fall back to a single global bucket.
    buckets = defaultdict(list)
    for row in rows:
        ts = _parse_ts(row.get("timestamp"))
        if ts is None:
            continue
        port = str(row.get("port", "unknown"))
        buckets[(port, ts.replace(second=ts.second // 60 * 60, microsecond=0))].append(row)

    for (port, window_start), bucket in sorted(buckets.items()):
        # Only 54-byte frames count toward the flood: macof forges 54-byte
        # frames, so a burst of unique MACs in other traffic (e.g. the DHCP
        # starvation burst, 342-byte frames) must not trip this rule.
        macs = {_norm_mac(r.get("src_mac")) for r in bucket
                if _norm_len(r.get("frame_len")) == MAC_FLOOD_FRAME_LEN
                and _norm_mac(r.get("src_mac"))}
        small_frames = sum(
            1 for r in bucket if _norm_len(r.get("frame_len")) == MAC_FLOOD_FRAME_LEN
        )
        if len(macs) >= MAC_FLOOD_UNIQUE_MACS:
            window_end = window_start + timedelta(minutes=1)
            alerts.append(_alert(
                alert_id=f"mac-flood-{port}-{window_start:%Y%m%d%H%M}",
                rule="MAC-FLOOD-01",
                title="MAC flooding terdeteksi",
                severity="high",
                src=f"switch port {port}",
                evidence=(
                    f"{len(macs)} alamat MAC sumber berbeda terlihat pada port {port} "
                    f"dalam 60 detik ({window_start:%H:%M:%S}–{window_end:%H:%M:%S}); "
                    f"{small_frames} di antaranya berukuran {MAC_FLOOD_FRAME_LEN} byte "
                    f"(pola khas macof). Normalnya satu port hanya melihat sedikit MAC."
                ),
                first_seen=window_start,
                last_seen=window_end,
            ))
    return alerts


def detect_dhcp_starvation(rows):
    """A flood of DHCP DISCOVER packets exhausting the server's address pool.

    yersinia sends thousands of DISCOVER messages with spoofed MACs and
    distinct Transaction IDs, so the DHCP server hands out every lease and
    legitimate clients get no address. Real lab example: 3.306.566 DISCOVER
    packets, Transaction ID 0x643c9869, server port 68.
    """
    alerts = []
    buckets = defaultdict(list)
    for row in rows:
        ts = _parse_ts(row.get("timestamp"))
        if ts is None:
            continue
        if not _is_dhcp_discover(row):
            continue
        buckets[ts.replace(second=ts.second // 60 * 60, microsecond=0)].append(row)

    for window_start, bucket in sorted(buckets.items()):
        if len(bucket) >= DHCP_STARVATION_DISCOVERS:
            txids = {str(r.get("info", "")).split("0x")[-1].split()[0]
                     for r in bucket if "0x" in str(r.get("info", ""))}
            macs = {_norm_mac(r.get("src_mac")) for r in bucket}
            window_end = window_start + timedelta(minutes=1)
            alerts.append(_alert(
                alert_id=f"dhcp-starve-{window_start:%Y%m%d%H%M}",
                rule="DHCP-STARVE-01",
                title="DHCP starvation terdeteksi",
                severity="critical",
                src="DHCP server (port 68)",
                evidence=(
                    f"{len(bucket)} paket DHCP DISCOVER dalam 60 detik "
                    f"({window_start:%H:%M:%S}–{window_end:%H:%M:%S}) dari "
                    f"{len(macs)} MAC sumber berbeda dengan {len(txids)} Transaction ID "
                    f"berbeda. Pola khas yersinia: membanjiri server sampai pool alamat habis."
                ),
                first_seen=window_start,
                last_seen=window_end,
            ))
    return alerts


def detect_arp_poisoning(rows):
    """One IP address claimed by two or more different MAC addresses.

    In ARP poisoning (Cain & Abel, hping3) the attacker answers ARP requests
    for the victim/gateway IP with its own MAC, so traffic is redirected.
    Wireshark flags this as "Duplicate IP address detected". Real lab
    example: 10.10.1.11 vs 10.10.1.13.
    """
    alerts = []
    ip_to_macs = defaultdict(set)
    ip_to_rows = defaultdict(list)
    for row in rows:
        proto = str(row.get("protocol", "")).upper()
        if proto != "ARP":
            continue
        src_ip = _norm_ip(row.get("src_ip"))
        src_mac = _norm_mac(row.get("src_mac"))
        if src_ip and src_mac:
            ip_to_macs[src_ip].add(src_mac)
            ip_to_rows[src_ip].append(row)

    for ip, macs in sorted(ip_to_macs.items()):
        if len(macs) >= ARP_POISON_MIN_MACS:
            bucket = ip_to_rows[ip]
            times = [_parse_ts(r.get("timestamp")) for r in bucket]
            times = [t for t in times if t is not None]
            alerts.append(_alert(
                alert_id=f"arp-poison-{ip.replace('.', '-')}",
                rule="ARP-POISON-01",
                title="ARP poisoning terdeteksi",
                severity="critical",
                src=ip,
                evidence=(
                    f"Alamat IP {ip} diklaim oleh {len(macs)} MAC berbeda: "
                    f"{', '.join(sorted(macs))}. Salah satunya adalah penyerang "
                    f"yang menjawab ARP request untuk IP ini (Duplicate IP di Wireshark)."
                ),
                first_seen=min(times) if times else None,
                last_seen=max(times) if times else None,
            ))
    return alerts


def detect_port_scan(rows):
    """One source IP probing many distinct destination ports in a short window."""
    alerts = []
    buckets = defaultdict(lambda: defaultdict(set))
    times = defaultdict(list)
    for row in rows:
        ts = _parse_ts(row.get("timestamp"))
        if ts is None:
            continue
        if str(row.get("protocol", "")).upper() not in ("TCP", "UDP"):
            continue
        src_ip = _norm_ip(row.get("src_ip"))
        dst_port = _norm_port(row.get("dst_port"))
        if not src_ip or dst_port is None:
            continue
        window = ts.replace(second=ts.second // 60 * 60, microsecond=0)
        buckets[(src_ip, window)][dst_port].add(ts)
        times[(src_ip, window)].append(ts)

    for (src_ip, window_start), ports in sorted(buckets.items()):
        if len(ports) >= PORT_SCAN_MIN_PORTS:
            window_end = window_start + timedelta(minutes=1)
            alerts.append(_alert(
                alert_id=f"port-scan-{src_ip.replace('.', '-')}-{window_start:%Y%m%d%H%M}",
                rule="PORT-SCAN-01",
                title="Port scan terdeteksi",
                severity="medium",
                src=src_ip,
                evidence=(
                    f"{src_ip} menghubungi {len(ports)} port tujuan berbeda "
                    f"dalam 60 detik ({window_start:%H:%M:%S}–{window_end:%H:%M:%S}): "
                    f"port {', '.join(str(p) for p in sorted(ports)[:10])}"
                    f"{' …' if len(ports) > 10 else ''}. Pola khas pemindaian port "
                    f"sebelum serangan lanjutan."
                ),
                first_seen=window_start,
                last_seen=window_end,
            ))
    return alerts


def analyze(rows):
    """Run every detector over ``rows`` and return alerts sorted by severity."""
    alerts = []
    alerts.extend(detect_mac_flooding(rows))
    alerts.extend(detect_dhcp_starvation(rows))
    alerts.extend(detect_arp_poisoning(rows))
    alerts.extend(detect_port_scan(rows))
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: (severity_rank.get(a["severity"], 9),
                               a["first_seen"] or ""))
    return alerts


def summarize(rows, alerts):
    """Dashboard counters derived from the same rows and alerts."""
    protocols = Counter(str(r.get("protocol", "unknown")).upper() for r in rows)
    severities = Counter(a["severity"] for a in alerts)
    return {
        "total_packets": len(rows),
        "total_alerts": len(alerts),
        "by_severity": {
            "critical": severities.get("critical", 0),
            "high": severities.get("high", 0),
            "medium": severities.get("medium", 0),
            "low": severities.get("low", 0),
        },
        "by_protocol": dict(sorted(protocols.items(), key=lambda kv: -kv[1])),
        "unique_src_ips": len({_norm_ip(r.get("src_ip")) for r in rows if _norm_ip(r.get("src_ip"))}),
        "unique_src_macs": len({_norm_mac(r.get("src_mac")) for r in rows if _norm_mac(r.get("src_mac"))}),
    }
