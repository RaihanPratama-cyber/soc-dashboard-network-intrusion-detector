"""Unit tests for the SOC detector rules and the Flask app."""

import csv
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector import (  # noqa: E402
    analyze,
    detect_arp_poisoning,
    detect_dhcp_starvation,
    detect_mac_flooding,
    detect_port_scan,
    summarize,
)
from app import app  # noqa: E402

DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "data", "sample_attacks.csv")


def row(ts, **over):
    base = {
        "timestamp": ts, "src_mac": "00:1a:2b:3c:4d:5e",
        "dst_mac": "ff:ff:ff:ff:ff:ff", "src_ip": "10.10.1.11",
        "dst_ip": "10.10.1.13", "src_port": "1234", "dst_port": "80",
        "protocol": "TCP", "frame_len": "120", "info": "", "port": "Fa0/1",
    }
    base.update(over)
    return base


# --- MAC flooding -----------------------------------------------------------
def test_mac_flooding_detected():
    rows = [row(f"2026-11-12T10:00:{i:02d}", src_mac=f"00:00:00:00:00:{i:02x}",
                frame_len="54", protocol="Ethernet")
            for i in range(60)]
    alerts = detect_mac_flooding(rows)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "MAC-FLOOD-01"
    assert alerts[0]["severity"] == "high"
    assert "60" in alerts[0]["evidence"]


def test_mac_flooding_not_triggered_by_few_macs():
    rows = [row(f"2026-11-12T10:00:{i:02d}", src_mac=f"00:00:00:00:00:{i:02x}")
            for i in range(5)]
    assert detect_mac_flooding(rows) == []


# --- DHCP starvation --------------------------------------------------------
def test_dhcp_starvation_detected():
    rows = [row(f"2026-11-12T10:00:{i % 60:02d}",
                src_mac=f"aa:bb:cc:00:00:{i:02x}", protocol="DHCP",
                dst_port="67",
                info=f"DHCP Discover - Transaction ID 0x{i:08x}")
            for i in range(120)]
    alerts = detect_dhcp_starvation(rows)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "DHCP-STARVE-01"
    assert alerts[0]["severity"] == "critical"
    assert "120" in alerts[0]["evidence"]


def test_dhcp_starvation_ignores_non_discover():
    rows = [row(f"2026-11-12T10:00:{i % 60:02d}", protocol="DHCP",
                info="DHCP Offer - Transaction ID 0x00000001")
            for i in range(150)]
    assert detect_dhcp_starvation(rows) == []


# --- ARP poisoning ----------------------------------------------------------
def test_arp_poisoning_detected():
    rows = [
        row("2026-11-12T10:00:01", protocol="ARP", src_ip="10.10.1.11",
            src_mac="00:1a:2b:3c:4d:5e", info="ARP reply"),
        row("2026-11-12T10:00:02", protocol="ARP", src_ip="10.10.1.11",
            src_mac="aa:bb:cc:11:22:33", info="ARP reply"),
    ]
    alerts = detect_arp_poisoning(rows)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "ARP-POISON-01"
    assert "10.10.1.11" in alerts[0]["evidence"]
    assert "aa:bb:cc:11:22:33" in alerts[0]["evidence"]


def test_arp_poisoning_not_triggered_by_single_mac():
    rows = [row("2026-11-12T10:00:01", protocol="ARP", src_ip="10.10.1.11",
                src_mac="00:1a:2b:3c:4d:5e")]
    assert detect_arp_poisoning(rows) == []


# --- Port scan --------------------------------------------------------------
def test_port_scan_detected():
    rows = [row(f"2026-11-12T10:00:{i:02d}", src_ip="10.10.1.99",
                dst_port=str(1000 + i), protocol="TCP", info="TCP SYN")
            for i in range(20)]
    alerts = detect_port_scan(rows)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "PORT-SCAN-01"
    assert "10.10.1.99" in alerts[0]["evidence"]


def test_port_scan_not_triggered_by_few_ports():
    rows = [row("2026-11-12T10:00:01", src_ip="10.10.1.99",
                dst_port="80", protocol="TCP")]
    assert detect_port_scan(rows) == []


# --- Sample dataset + summary ----------------------------------------------
def test_sample_dataset_triggers_all_four_attacks():
    with open(DATA_FILE, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    alerts = analyze(rows)
    rules = {a["rule"] for a in alerts}
    assert rules == {"MAC-FLOOD-01", "DHCP-STARVE-01", "ARP-POISON-01", "PORT-SCAN-01"}
    summary = summarize(rows, alerts)
    assert summary["total_packets"] == len(rows)
    assert summary["by_severity"]["critical"] == 2  # DHCP + ARP


def test_analyze_empty_input_returns_no_alerts():
    assert analyze([]) == []


# --- Flask app --------------------------------------------------------------
@pytest.fixture()
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_overview_page_returns_200(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"SOC Dashboard" in resp.data
    assert b"MAC flooding" in resp.data


def test_alerts_page_returns_200(client):
    resp = client.get("/alerts")
    assert resp.status_code == 200
    assert b"DHCP starvation" in resp.data


def test_logs_page_returns_200(client):
    resp = client.get("/logs")
    assert resp.status_code == 200
    assert b"sample_attacks.csv" in resp.data


def test_api_alerts(client):
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    assert resp.get_json()["total"] == 4


def test_api_check_with_rows(client):
    resp = client.post("/api/check", json={"rows": [
        row("2026-11-12T10:00:01", protocol="ARP", src_ip="10.10.1.11",
            src_mac="00:1a:2b:3c:4d:5e"),
        row("2026-11-12T10:00:02", protocol="ARP", src_ip="10.10.1.11",
            src_mac="aa:bb:cc:11:22:33"),
    ]})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total_alerts"] == 1
    assert data["alerts"][0]["rule"] == "ARP-POISON-01"


def test_api_check_with_csv_text(client):
    csv_text = ("timestamp,src_mac,dst_mac,src_ip,dst_ip,src_port,dst_port,"
                "protocol,frame_len,info\n"
                "2026-11-12T10:00:01,aa:bb:cc:00:00:01,ff:ff:ff:ff:ff:ff,"
                "0.0.0.0,255.255.255.255,68,67,DHCP,342,"
                "DHCP Discover - Transaction ID 0x00000001\n")
    resp = client.post("/api/check", json={"csv": csv_text})
    assert resp.status_code == 200
    assert resp.get_json()["total_rows"] == 1


def test_api_check_rejects_bad_body(client):
    resp = client.post("/api/check", json={"nope": True})
    assert resp.status_code == 400
    assert "error" in resp.get_json()
