"""
Generates a realistic test PCAP file with DNS, HTTP, ICMP, and TCP handshakes.
"""
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap
import time

def generate_sample_pcap(output_path: str):
    packets = []
    base_time = 1710500000.0

    # 1. ARP Request & Reply
    # 2. DNS query & response
    pkt_dns_q = Ether()/IP(src="192.168.1.105", dst="8.8.8.8")/UDP(sport=53210, dport=53)/DNS(rd=1, qd=DNSQR(qname="cybershield.lab"))
    pkt_dns_q.time = base_time + 0.1
    packets.append(pkt_dns_q)

    # 3. HTTP 3-Way Handshake: SYN -> SYN-ACK -> ACK
    syn = Ether()/IP(src="192.168.1.105", dst="192.168.1.50")/TCP(sport=44321, dport=80, flags="S", seq=1000)
    syn.time = base_time + 0.2
    packets.append(syn)

    syn_ack = Ether()/IP(src="192.168.1.50", dst="192.168.1.105")/TCP(sport=80, dport=44321, flags="SA", seq=5000, ack=1001)
    syn_ack.time = base_time + 0.22
    packets.append(syn_ack)

    ack = Ether()/IP(src="192.168.1.105", dst="192.168.1.50")/TCP(sport=44321, dport=80, flags="A", seq=1001, ack=5001)
    ack.time = base_time + 0.23
    packets.append(ack)

    # 4. HTTP GET request & 200 OK Response
    http_req = Ether()/IP(src="192.168.1.105", dst="192.168.1.50")/TCP(sport=44321, dport=80, flags="PA", seq=1001, ack=5001)/Raw(load="GET /index.html HTTP/1.1\r\nHost: 192.168.1.50\r\nUser-Agent: Mozilla/5.0 CyberShield\r\n\r\n")
    http_req.time = base_time + 0.25
    packets.append(http_req)

    http_resp = Ether()/IP(src="192.168.1.50", dst="192.168.1.105")/TCP(sport=80, dport=44321, flags="PA", seq=5001, ack=1080)/Raw(load="HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n<html><body>CyberShield Lab Secured</body></html>")
    http_resp.time = base_time + 0.28
    packets.append(http_resp)

    # 5. ICMP Ping echo request and reply
    ping_req = Ether()/IP(src="192.168.1.105", dst="192.168.1.1")/ICMP(type=8, code=0, id=1, seq=1)
    ping_req.time = base_time + 0.5
    packets.append(ping_req)

    ping_rep = Ether()/IP(src="192.168.1.1", dst="192.168.1.105")/ICMP(type=0, code=0, id=1, seq=1)
    ping_rep.time = base_time + 0.52
    packets.append(ping_rep)

    # 6. Port Scan traffic (SYN to ports 21, 22, 23, 25, 443)
    for p in [21, 22, 23, 25, 443]:
        scan_pkt = Ether()/IP(src="192.168.1.105", dst="192.168.1.50")/TCP(sport=50000+p, dport=p, flags="S", seq=2000)
        scan_pkt.time = base_time + 1.0 + (p * 0.01)
        packets.append(scan_pkt)

    wrpcap(output_path, packets)
    print(f"Sample PCAP successfully written to {output_path} with {len(packets)} packets.")

if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "samples/sample_capture.pcap"
    generate_sample_pcap(out)
