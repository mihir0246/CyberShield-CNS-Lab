import pytest
from cybershield.services.traffic_analysis.dos_simulator import DosSimulator


def test_dos_simulation_mitigation():
    # Run mitigated simulation
    res_mitigated = DosSimulator.run_simulation(
        attack_type="SYN Flood",
        baseline_rate=100,
        peak_attack_rate=2000,
        duration_seconds=10,
        apply_mitigation=True,
        rate_limit_threshold=300,
    )
    assert res_mitigated["apply_mitigation"] is True
    assert res_mitigated["total_packets_dropped"] > 0
    assert len(res_mitigated["timeline"]) == 10

    # Run unmitigated simulation
    res_unmitigated = DosSimulator.run_simulation(
        attack_type="SYN Flood",
        baseline_rate=100,
        peak_attack_rate=2000,
        duration_seconds=10,
        apply_mitigation=False,
    )
    assert res_unmitigated["apply_mitigation"] is False
    # Unmitigated peak latency should be significantly higher
    assert res_unmitigated["peak_latency_ms"] > res_mitigated["peak_latency_ms"]


def test_traffic_spike_detection():
    # Generate test packet timestamps with a clear spike at t = 2.0s
    packets = []
    # 5 packets at t=0
    for _ in range(5):
        packets.append({"rel_time": 0.2})
    # 5 packets at t=1
    for _ in range(5):
        packets.append({"rel_time": 1.2})
    # 50 packets at t=2 (Burst / Spike)
    for _ in range(50):
        packets.append({"rel_time": 2.5})

    analysis = DosSimulator.analyze_traffic_spikes(packets, window_seconds=1.0)
    assert analysis["spikes_detected"] is True
    assert analysis["spike_count"] >= 1
    assert any(s["spike_factor"] > 2.0 for s in analysis["spike_events"])
