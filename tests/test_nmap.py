import pytest
from cybershield.services.network_scanning.nmap_service import NmapService


def test_nmap_xml_parsing(sample_nmap_xml_path):
    report = NmapService.load_sample_report(sample_nmap_xml_path)
    assert report["is_sample_data"] is True
    assert report["total_hosts"] == 1
    host = report["hosts"][0]
    assert host["ip"] == "127.0.0.1"

    # Verify parsed ports
    ports = host["ports"]
    open_ports = [p["port"] for p in ports if p["state"] == "open"]
    assert 22 in open_ports
    assert 80 in open_ports
    assert 443 in open_ports
    assert 5000 in open_ports


def test_nmap_target_guardrail():
    allowed = ["127.0.0.1", "localhost", "::1"]

    # Valid targets
    assert NmapService.validate_target("127.0.0.1", allowed) == "127.0.0.1"
    assert NmapService.validate_target("localhost", allowed) == "localhost"

    # Public IP / External target must be rejected
    with pytest.raises(ValueError, match="Unauthorized Target"):
        NmapService.validate_target("8.8.8.8", allowed)

    with pytest.raises(ValueError, match="Unauthorized Target"):
        NmapService.validate_target("192.168.1.100", allowed)

    # Shell injection attempt must be rejected
    with pytest.raises(ValueError, match="Malicious characters"):
        NmapService.validate_target("127.0.0.1; rm -rf /", allowed)
