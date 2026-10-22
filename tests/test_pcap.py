import pytest
from cybershield.services.packet_analysis.pcap_service import PcapService


def test_pcap_parsing(sample_pcap_path):
    parsed = PcapService.parse_pcap_file(sample_pcap_path)
    assert parsed["total_packets"] > 0
    assert len(parsed["packets"]) == parsed["total_packets"]
    assert "protocol_distribution" in parsed
    assert "top_talkers" in parsed

    # Check first packet attributes
    first_pkt = parsed["packets"][0]
    assert "number" in first_pkt
    assert "src_ip" in first_pkt
    assert "dst_ip" in first_pkt
    assert "protocol" in first_pkt


def test_pcap_filtering(sample_pcap_path):
    parsed = PcapService.parse_pcap_file(sample_pcap_path)
    packets = parsed["packets"]

    # Filter by TCP SYN
    syn_filtered = PcapService.filter_packets(packets, flag_filter="SYN")
    assert len(syn_filtered) > 0
    for p in syn_filtered:
        assert "SYN" in p["tcp_flags"]

    # Filter by Protocol HTTP
    http_filtered = PcapService.filter_packets(packets, protocol="HTTP")
    for p in http_filtered:
        assert p["protocol"] == "HTTP"


def test_pcap_csv_export(sample_pcap_path):
    parsed = PcapService.parse_pcap_file(sample_pcap_path)
    csv_out = PcapService.export_to_csv(parsed["packets"][:5])
    assert "number,rel_time,abs_time" in csv_out
    assert len(csv_out.splitlines()) == 6  # Header + 5 lines
