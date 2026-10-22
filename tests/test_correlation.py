import pytest
from cybershield.services.correlation.event_correlator import EventCorrelator


def test_event_correlation_engine():
    # Synthetic multi-source telemetry
    # 1. PCAP packets showing port probing from 192.168.1.105 across ports 21, 22, 80, 443
    pcap_pkts = [
        {"src_ip": "192.168.1.105", "dst_port": "21", "tcp_flags": "SYN"},
        {"src_ip": "192.168.1.105", "dst_port": "22", "tcp_flags": "SYN"},
        {"src_ip": "192.168.1.105", "dst_port": "80", "tcp_flags": "SYN"},
        {"src_ip": "192.168.1.105", "dst_port": "443", "tcp_flags": "SYN"},
    ]

    # 2. Snort alert matching port scan from same host
    snort_alerts = [
        {
            "src_ip": "192.168.1.105",
            "dst_port": "443",
            "signature": "ET SCAN Potential SSH Brute Force / Portscan",
            "sid": "2001219",
            "priority": 2,
            "protocol": "TCP",
        }
    ]

    # 3. Nmap open ports
    nmap_ports = [{"port": 22, "state": "open"}, {"port": 80, "state": "open"}]

    res = EventCorrelator.correlate(
        pcap_packets=pcap_pkts,
        snort_alerts=snort_alerts,
        nmap_ports=nmap_ports,
    )

    assert res["total_correlated_incidents"] >= 1
    recon_finding = next(f for f in res["findings"] if f["category"] == "Reconnaissance")
    assert recon_finding["primary_ip"] == "192.168.1.105"
    assert recon_finding["severity"] in ["HIGH", "MEDIUM"]
    assert len(recon_finding["evidence"]) >= 2
    assert len(res["timeline"]) > 0
