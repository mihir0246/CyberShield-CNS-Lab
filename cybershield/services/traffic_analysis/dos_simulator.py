"""
Controlled DoS Analysis and Traffic Simulation Service
Safe, non-disruptive analytical lab providing synthetic traffic modeling,
rate-limiting defense demonstrations, anomaly detection algorithms, and Hping3 parameter studies.
"""
import math
import random
from typing import Dict, Any, List


class DosSimulator:
    HPING3_PARAMETERS_GUIDE = [
        {
            "option": "-S / --syn",
            "meaning": "Set SYN TCP Flag",
            "purpose": "Simulates TCP SYN flood by sending connection initiation requests without completing the 3-way handshake.",
            "defensive_remedy": "Enable TCP SYN cookies (sysctl net.ipv4.tcp_syncookies=1), reduce SYN-ACK retransmissions.",
        },
        {
            "option": "-1 / --icmp",
            "meaning": "ICMP Mode",
            "purpose": "Sends ICMP Echo Requests (ping flood) to saturate incoming bandwidth or CPU interrupts.",
            "defensive_remedy": "Rate-limit ICMP at perimeter firewall / iptables, drop ping bursts exceeding 10 req/s.",
        },
        {
            "option": "-2 / --udp",
            "meaning": "UDP Mode",
            "purpose": "Sends UDP packets to random high ports, forcing victim to respond with ICMP 'Port Unreachable' packets.",
            "defensive_remedy": "Drop inbound UDP traffic on unassigned ports; rate-limit ICMP unreachable error generation.",
        },
        {
            "option": "-p / --destport <port>",
            "meaning": "Target Port",
            "purpose": "Specifies destination service port (e.g. 80 for HTTP, 443 for HTTPS, 53 for DNS).",
            "defensive_remedy": "Protect critical application ports behind reverse proxies with Layer-7 DDoS filtering.",
        },
        {
            "option": "--flood",
            "meaning": "Flood Mode",
            "purpose": "Sends packets as fast as possible without waiting for incoming replies.",
            "defensive_remedy": "Upstream scrubbing centers, BGP Anycast routing, Cloudflare/AWS Shield DDoS protection.",
        },
        {
            "option": "--rand-source",
            "meaning": "Spoof Random Source IP",
            "purpose": "Hides attacker identity and bypasses basic single-IP rate limits.",
            "defensive_remedy": "BCP 38 (Best Current Practice 38) ingress filtering by ISPs to drop spoofed packets; SYN cookies.",
        },
        {
            "option": "-c <count>",
            "meaning": "Packet Count Bounding",
            "purpose": "Strictly caps total packets sent (essential for educational/controlled testing).",
            "defensive_remedy": "Use conservative burst thresholds in network telemetry.",
        },
    ]

    @classmethod
    def run_simulation(
        cls,
        attack_type: str = "SYN Flood",
        baseline_rate: int = 100,  # packets per second
        peak_attack_rate: int = 2500,  # packets per second
        duration_seconds: int = 15,
        apply_mitigation: bool = True,
        mitigation_strategy: str = "Token Bucket Rate Limiting",
        rate_limit_threshold: int = 400,
    ) -> Dict[str, Any]:
        """
        Simulates a controlled traffic burst over time, modeling CPU utilization,
        latency degradation, packet drop ratios, and mitigation enforcement.
        """
        timeline = []
        total_packets = 0
        total_dropped = 0
        peak_latency = 5.0
        peak_cpu = 15.0
        anomaly_points = []

        # Normal server capacity parameters
        max_normal_capacity = 800  # packets/s before latency spikes
        server_collapse_capacity = 3000

        for sec in range(1, duration_seconds + 1):
            # Attack profile: ramp up from sec 4 to sec 11
            if sec < 4:
                # Baseline traffic
                current_incoming = int(baseline_rate + random.uniform(-15, 15))
                is_attack_active = False
            elif 4 <= sec <= 11:
                # Attack ramp and sustain
                progress = (sec - 3) / 8.0
                envelope = math.sin(progress * math.pi)
                attack_component = int(peak_attack_rate * envelope)
                current_incoming = int(baseline_rate + attack_component + random.uniform(-50, 50))
                is_attack_active = True
            else:
                # Post-attack recovery
                current_incoming = int(baseline_rate + random.uniform(-20, 20))
                is_attack_active = False

            total_packets += current_incoming

            # Apply mitigation if active
            passed_packets = current_incoming
            dropped_packets = 0
            if apply_mitigation and is_attack_active:
                if current_incoming > rate_limit_threshold:
                    passed_packets = rate_limit_threshold
                    dropped_packets = current_incoming - rate_limit_threshold
            elif not apply_mitigation and current_incoming > server_collapse_capacity:
                dropped_packets = int(current_incoming * 0.4)  # System buffer overflow
                passed_packets = current_incoming - dropped_packets

            total_dropped += dropped_packets

            # Latency and CPU modeling
            load_ratio = passed_packets / max_normal_capacity
            if apply_mitigation:
                # Server is protected by rate limiting
                sim_cpu = min(95.0, 15.0 + (passed_packets / max_normal_capacity) * 45.0)
                sim_latency = round(5.0 + (load_ratio ** 1.5) * 15.0 + random.uniform(0.5, 3.0), 1)
            else:
                # Unprotected server experiences buffer exhaustion & queuing delay
                sim_cpu = min(100.0, 15.0 + (current_incoming / max_normal_capacity) * 85.0)
                sim_latency = round(5.0 + (load_ratio ** 2.2) * 120.0 + random.uniform(2.0, 15.0), 1)

            if sim_latency > peak_latency:
                peak_latency = sim_latency
            if sim_cpu > peak_cpu:
                peak_cpu = sim_cpu

            # Anomaly trigger: traffic > 2x baseline
            is_anomaly = current_incoming > (baseline_rate * 2)
            if is_anomaly:
                anomaly_points.append(sec)

            timeline.append({
                "second": sec,
                "incoming_rate_pps": current_incoming,
                "passed_rate_pps": passed_packets,
                "dropped_rate_pps": dropped_packets,
                "latency_ms": sim_latency,
                "cpu_percent": round(sim_cpu, 1),
                "is_attack": is_attack_active,
                "anomaly_flag": is_anomaly,
            })

        return {
            "is_simulation": True,
            "simulation_notice": "CONTROLLED LAB SIMULATION: Computed using synthetic models and statistical queuing mathematics. No external traffic is transmitted.",
            "attack_type": attack_type,
            "duration_seconds": duration_seconds,
            "baseline_rate_pps": baseline_rate,
            "peak_attack_rate_pps": peak_attack_rate,
            "apply_mitigation": apply_mitigation,
            "mitigation_strategy": mitigation_strategy if apply_mitigation else "None (Unprotected Endpoint)",
            "rate_limit_threshold": rate_limit_threshold,
            "total_packets_simulated": total_packets,
            "total_packets_dropped": total_dropped,
            "drop_percentage": round((total_dropped / total_packets) * 100.0, 1) if total_packets > 0 else 0.0,
            "peak_latency_ms": peak_latency,
            "peak_cpu_percent": peak_cpu,
            "anomalies_detected_count": len(anomaly_points),
            "timeline": timeline,
            "defense_recommendations": [
                "1. Token Bucket Rate Limiting: Restrict maximum incoming burst rates per source IP to prevent resource exhaustion.",
                "2. SYN Cookies (RFC 4987): Eliminate half-open connection state tables in kernel memory during SYN floods.",
                "3. Upstream BGP Scrubbing & Anycast: Distribute high volumetric floods across global edge points of presence.",
                "4. Dynamic Blackholing / RTBH: Null-route targeted IP prefixes upstream when volumetric threshold is breached.",
            ],
        }

    @classmethod
    def analyze_traffic_spikes(cls, packet_records: List[Dict[str, Any]], window_seconds: float = 1.0) -> Dict[str, Any]:
        """
        Detects traffic spikes from PCAP packet records by calculating packets per time bucket.
        """
        if not packet_records:
            return {"spikes_detected": False, "buckets": []}

        buckets: Dict[int, int] = {}
        for pkt in packet_records:
            t = float(pkt.get("rel_time", 0.0))
            bucket_idx = int(t // window_seconds)
            buckets[bucket_idx] = buckets.get(bucket_idx, 0) + 1

        if not buckets:
            return {"spikes_detected": False, "buckets": []}

        rates = list(buckets.values())
        avg_rate = sum(rates) / len(rates)
        spike_threshold = max(5, avg_rate * 2.0)

        spike_events = []
        bucket_list = []
        for b_idx in sorted(buckets.keys()):
            count = buckets[b_idx]
            is_spike = count > spike_threshold
            bucket_list.append({
                "time_window_sec": f"{b_idx * window_seconds}-{(b_idx + 1) * window_seconds}",
                "packet_count": count,
                "is_spike": is_spike,
            })
            if is_spike:
                spike_events.append({
                    "time_window": f"{b_idx * window_seconds}-{(b_idx + 1) * window_seconds}s",
                    "packet_count": count,
                    "spike_factor": round(count / avg_rate, 2) if avg_rate > 0 else count,
                })

        return {
            "average_packets_per_window": round(avg_rate, 2),
            "spike_threshold": round(spike_threshold, 2),
            "spikes_detected": len(spike_events) > 0,
            "spike_count": len(spike_events),
            "spike_events": spike_events,
            "buckets": bucket_list,
        }
