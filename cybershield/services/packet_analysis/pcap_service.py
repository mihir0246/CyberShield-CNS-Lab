"""
Packet Analysis Service (Wireshark & PCAP Parser)
Parses PCAP/PCAPNG files via Scapy, extracts packet layers, applies filters,
generates protocol distributions, and handles capture mode explanations.
"""
import io
import csv
import datetime
from typing import List, Dict, Any, Optional
from scapy.all import rdpcap, PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw


class PcapService:
    @classmethod
    def parse_pcap_file(cls, file_path: str, max_packets: int = 500) -> Dict[str, Any]:
        """
        Parses a PCAP/PCAPNG file and returns structured packet list and summary metrics.
        """
        packets_data: List[Dict[str, Any]] = []
        protocol_counts: Dict[str, int] = {}
        ip_talkers: Dict[str, int] = {}
        first_ts: Optional[float] = None
        last_ts: Optional[float] = None

        try:
            # PcapReader allows memory-efficient packet-by-packet reading
            with PcapReader(file_path) as pcap_reader:
                for idx, pkt in enumerate(pcap_reader):
                    if idx >= max_packets:
                        break

                    pkt_time = float(pkt.time)
                    if first_ts is None:
                        first_ts = pkt_time
                    last_ts = pkt_time
                    rel_time = round(pkt_time - first_ts, 4)

                    src_ip = "Unknown"
                    dst_ip = "Unknown"
                    protocol = "Ethernet"
                    src_port = "-"
                    dst_port = "-"
                    tcp_flags = []
                    info = pkt.summary()

                    if IP in pkt:
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        protocol = "IPv4"
                        ip_talkers[src_ip] = ip_talkers.get(src_ip, 0) + 1
                    elif IPv6 in pkt:
                        src_ip = pkt[IPv6].src
                        dst_ip = pkt[IPv6].dst
                        protocol = "IPv6"
                        ip_talkers[src_ip] = ip_talkers.get(src_ip, 0) + 1
                    elif ARP in pkt:
                        src_ip = pkt[ARP].psrc
                        dst_ip = pkt[ARP].pdst
                        protocol = "ARP"
                        info = f"ARP Who has {dst_ip}? Tell {src_ip}"

                    if TCP in pkt:
                        protocol = "TCP"
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport

                        # Identify common application layer protocols
                        if dst_port == 80 or src_port == 80:
                            protocol = "HTTP"
                        elif dst_port == 443 or src_port == 443:
                            protocol = "TLS/HTTPS"
                        elif dst_port == 22 or src_port == 22:
                            protocol = "SSH"

                        # Decode TCP flags
                        flags_int = int(pkt[TCP].flags)
                        if flags_int & 0x02:
                            tcp_flags.append("SYN")
                        if flags_int & 0x10:
                            tcp_flags.append("ACK")
                        if flags_int & 0x01:
                            tcp_flags.append("FIN")
                        if flags_int & 0x04:
                            tcp_flags.append("RST")
                        if flags_int & 0x08:
                            tcp_flags.append("PSH")
                        if flags_int & 0x20:
                            tcp_flags.append("URG")

                    elif UDP in pkt:
                        protocol = "UDP"
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                        if dst_port == 53 or src_port == 53 or DNS in pkt:
                            protocol = "DNS"
                        elif dst_port in (67, 68) or src_port in (67, 68):
                            protocol = "DHCP"
                    elif ICMP in pkt:
                        protocol = "ICMP"
                        icmp_type = pkt[ICMP].type
                        icmp_code = pkt[ICMP].code
                        info = f"ICMP Type {icmp_type} (Echo Request/Reply) Code {icmp_code}"

                    protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

                    # Payload preview
                    payload_preview = ""
                    if Raw in pkt:
                        raw_data = pkt[Raw].load[:64]
                        payload_preview = repr(raw_data)

                    packets_data.append({
                        "number": idx + 1,
                        "rel_time": rel_time,
                        "abs_time": datetime.datetime.fromtimestamp(pkt_time).strftime("%H:%M:%S.%f")[:-3],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": protocol,
                        "src_port": str(src_port),
                        "dst_port": str(dst_port),
                        "length": len(pkt),
                        "tcp_flags": ", ".join(tcp_flags) if tcp_flags else "-",
                        "info": info[:100],
                        "payload_preview": payload_preview,
                    })

        except Exception as e:
            raise ValueError(f"Error reading PCAP file: {str(e)}")

        duration = round((last_ts - first_ts), 3) if (first_ts and last_ts) else 0.0

        # Sort top talkers
        sorted_talkers = [
            {"ip": ip, "count": count}
            for ip, count in sorted(ip_talkers.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        return {
            "total_packets": len(packets_data),
            "duration_seconds": duration,
            "protocol_distribution": protocol_counts,
            "top_talkers": sorted_talkers,
            "packets": packets_data,
        }

    @classmethod
    def filter_packets(
        cls,
        packets: List[Dict[str, Any]],
        protocol: Optional[str] = None,
        ip_filter: Optional[str] = None,
        port_filter: Optional[str] = None,
        flag_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Filters packet list by protocol, IP address, port number, or TCP flag."""
        filtered = []
        proto_norm = protocol.strip().upper() if protocol else None
        ip_norm = ip_filter.strip().lower() if ip_filter else None
        port_norm = port_filter.strip() if port_filter else None
        flag_norm = flag_filter.strip().upper() if flag_filter else None

        for pkt in packets:
            if proto_norm and proto_norm != "ALL":
                if proto_norm != pkt["protocol"].upper():
                    continue

            if ip_norm:
                if ip_norm not in pkt["src_ip"].lower() and ip_norm not in pkt["dst_ip"].lower():
                    continue

            if port_norm:
                if port_norm != str(pkt["src_port"]) and port_norm != str(pkt["dst_port"]):
                    continue

            if flag_norm:
                if flag_norm not in pkt["tcp_flags"].upper():
                    continue

            filtered.append(pkt)

        return filtered

    @classmethod
    def export_to_csv(cls, packets: List[Dict[str, Any]]) -> str:
        """Exports parsed packets to RFC 4180 CSV string."""
        output = io.StringIO()
        fieldnames = [
            "number",
            "rel_time",
            "abs_time",
            "src_ip",
            "dst_ip",
            "protocol",
            "src_port",
            "dst_port",
            "length",
            "tcp_flags",
            "info",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for p in packets:
            writer.writerow(p)
        return output.getvalue()

    @classmethod
    def get_capture_mode_info(cls) -> Dict[str, Any]:
        """Explains promiscuous vs non-promiscuous capture modes and probes OS driver status."""
        import platform
        os_name = platform.system()
        has_winpcap = False
        if os_name == "Windows":
            try:
                from scapy.config import conf
                has_winpcap = bool(getattr(conf, "use_pcap", False))
            except Exception:
                has_winpcap = False

        return {
            "os_environment": os_name,
            "live_capture_driver_installed": has_winpcap if os_name == "Windows" else True,
            "modes_comparison": {
                "non_promiscuous": {
                    "name": "Standard / Non-Promiscuous Mode",
                    "behavior": "Network interface controller (NIC) filters and processes only frames addressed to its specific MAC address, broadcast frames (FF:FF:FF:FF:FF:FF), and joined multicast groups. All other frames are silently dropped at the hardware PHY/MAC layer.",
                    "security_impact": "Lower processing overhead, preserves host privacy, standard operational mode.",
                },
                "promiscuous": {
                    "name": "Promiscuous Mode",
                    "behavior": "NIC hardware filter is disabled; the interface passes all frames seen on the physical wire/air up to the operating system packet capture buffer regardless of destination MAC address.",
                    "switched_lan_reality": "IMPORTANT: On modern switched Ethernet networks (micro-segmented LANs), switch ASIC forwarding tables direct unicast packets only to the specific physical switch port connected to the recipient. Therefore, turning on promiscuous mode locally DOES NOT magically capture traffic between other workstations unless connected via a legacy hub, port mirroring (SPAN), or ARP cache poisoning.",
                },
            },
            "wireshark_instructions": [
                "1. Download and install Wireshark from https://www.wireshark.org/ (includes Npcap on Windows).",
                "2. Launch Wireshark and open any .pcap or .pcapng file generated by CyberShield (File -> Open).",
                "3. Use Wireshark display filters such as 'ip.addr == 192.168.1.1', 'tcp.port == 80', or 'http'.",
                "4. Right-click any TCP packet and select 'Follow -> TCP Stream' to inspect complete reassembled conversations.",
                "5. Inspect the Statistics menu -> 'Protocol Hierarchy' and 'Conversations' for traffic telemetry.",
            ],
        }
