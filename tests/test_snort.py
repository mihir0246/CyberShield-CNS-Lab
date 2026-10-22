import pytest
from cybershield.services.snort.snort_service import SnortService


def test_snort_rule_explainer():
    rule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"LAB WEB-MISC Directory Traversal (../)"; content:"../"; nocase; sid:1000002; rev:1; priority:1;)'
    exp = SnortService.explain_rule(rule)
    assert exp["valid_syntax"] is True
    assert exp["header"]["action"] == "ALERT"
    assert exp["header"]["protocol"] == "TCP"
    assert exp["metadata"]["sid"] == "1000002"
    assert exp["metadata"]["priority"] == "1"


def test_snort_fast_log_parser(sample_snort_log_path):
    res = SnortService.load_log_file(sample_snort_log_path)
    assert res["total_alerts"] == 7
    first_alert = res["alerts"][0]
    assert "timestamp" in first_alert
    assert "signature" in first_alert
    assert "src_ip" in first_alert
    assert "dst_ip" in first_alert
    assert first_alert["protocol"] in ["TCP", "UDP", "ICMP"]


def test_snort_csv_export(sample_snort_log_path):
    res = SnortService.load_log_file(sample_snort_log_path)
    csv_str = SnortService.export_alerts_csv(res["alerts"][:3])
    assert "timestamp,sid,signature,classification" in csv_str
    assert len(csv_str.splitlines()) == 4  # Header + 3 records
