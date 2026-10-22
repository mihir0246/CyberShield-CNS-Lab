# CyberShield System Architecture & Security Specification

---

## 1. High-Level Architectural Model

CyberShield adopts a decoupled, multi-layered architectural model combining modern Python application engineering with strict ethical defensive guardrails.

```
+-------------------------------------------------------------------------+
|                           CLIENT TIER (BROWSER)                         |
|  Bootstrap 5.3 + Dark Navy Theme | Chart.js Data Visualizations        |
|  AJAX Fetch Engine (cybershield.js) | Toast System | Responsive UI      |
+-------------------------------------------------------------------------+
                                    |
                         JSON / Multi-part HTTP
                                    |
+-------------------------------------------------------------------------+
|                        FLASK APPLICATION ROUTING TIER                    |
|  cybershield/app.py (Application Factory)                               |
|  CSRF Protection (Flask-WTF) | Security Headers Middleware              |
|  13 Modular Blueprints:                                                 |
|    - main_bp         - ciphers_bp     - hill_bp       - rsa_bp          |
|    - dh_bp           - hash_bp        - pcap_bp       - nmap_bp         |
|    - dos_bp          - snort_bp       - correlation_bp- history_bp      |
|    - docs_bp                                                            |
+-------------------------------------------------------------------------+
                                    |
+-------------------------------------------------------------------------+
|                          DOMAIN SERVICES TIER                           |
|  ciphers/          -> CaesarCipher, VernamCipher, RailFenceCipher       |
|  hill/             -> HillCipher (2x2 / 3x3 Modular Inversion mod 26)   |
|  rsa/              -> RSAService (cryptography OAEP-SHA256, Benchmarks) |
|  diffie_hellman/   -> DHService (MODP Key Exchange, HKDF-SHA256)        |
|  hashing/          -> HashService (MD5 vs SHA-256 Multi-size Suite)     |
|  packet_analysis/  -> PcapService (Scapy Demultiplexer, CSV Exporter)   |
|  network_scanning/ -> NmapService (Subprocess Safe Runner, XML Parser)  |
|  traffic_analysis/ -> DosSimulator (Queuing Models, Token Bucket)       |
|  snort/            -> SnortService (Rule Explainer, Fast Log Parser)    |
|  correlation/      -> EventCorrelator (Multi-domain Temporal Fusion)    |
+-------------------------------------------------------------------------+
                    |                               |
                    v                               v
+-----------------------------+     +-----------------------------------+
|      DATA PERSISTENCE       |     |        EXTERNAL DEPENDENCIES      |
|  SQLite (cybershield.db)    |     |  Scapy Engine (Offline PCAPs)     |
|  SQLAlchemy 2.1 ORM Models  |     |  Nmap CLI (Target-Guarded)        |
|  Zero Plaintext Retention   |     |  Snort CLI / Sample Logs          |
+-----------------------------+     +-----------------------------------+
```

---

## 2. Component Design & Modularity

### 2.1 Cryptographic Core
- **Isolation of Secrets:** Plaintext messages and private asymmetric keys exist only in ephemeral process memory during calculation. The database only records audit metadata (e.g., input byte size, algorithm type, execution time in milliseconds).
- **Standards Compliance:** Asymmetric encryption utilizes RFC 8017 PKCS#1 v2.2 RSA-OAEP with SHA-256 and MGF1. Key exchange derives symmetric session keys using HKDF-SHA256 (RFC 5869).
- **Mathematical Rigor:** The Hill cipher service explicitly computes modular determinants via Gaussian elimination / cofactor expansion modulo 26 and validates that `gcd(det, 26) == 1` before allowing encryption or decryption.

### 2.2 Packet Telemetry & Network Services
- **Scapy Packet Streaming:** Uses `PcapReader` to process multi-megabyte PCAP/PCAPNG files frame-by-frame with bounded memory utilization.
- **Controlled Subprocess Execution:** Nmap scans are invoked using `subprocess.run(cmd, shell=False)` with strictly whitelisted arguments and absolute path resolution. Shell interpolation and user-injected flag injection are impossible by design.
- **Graceful Tool Fallback:** If Nmap or Snort are missing on host workstations, the services automatically detect their absence, query system PATH, and switch to pre-compiled authentic lab telemetry (`samples/sample_nmap.xml` and `samples/sample_snort.log`), preventing crashes.

---

## 3. Data Flow Patterns

### 3.1 Network Packet Ingestion & Analysis
```
[User Uploads PCAP]
        |
        v
[PcapService.parse_pcap_file()]
        |
        +---> [Scapy Dissects Ethernet / IP / TCP / UDP / ICMP / DNS]
        +---> [Extracts relative timestamps, ports, flags, payload preview]
        +---> [Computes protocol distribution & top talkers]
        |
        v
[PcapSummary Model Stored in SQLite]
        |
        v
[Chart.js Renders Protocol Doughnut + Dissected Frames Table]
```

### 3.2 Cross-Domain Security Event Correlation
```
  [Scapy PCAP Packets]     [Snort Alert Logs]     [Nmap Open Ports]     [DoS Traffic Bursts]
           \                       |                     |                      /
            \                      |                     |                     /
             v                     v                     v                    v
          +--------------------------------------------------------------------+
          |              EventCorrelator.correlate() Engine                    |
          |  1. Groups events by Source IP, Destination Port, & Time Window   |
          |  2. Matches SYN Probes in PCAP with Portscan Signatures in Snort  |
          |  3. Links Web Exploitation Alerts (../) to Target Port 80          |
          |  4. Flags Anomaly Spikes breaching 2x baseline rate               |
          |  5. Assigns Severity (CRITICAL, HIGH, MEDIUM) & Confidence Score   |
          +--------------------------------------------------------------------+
                                           |
                                           v
                         [CorrelatedFindingModel Records]
                                           |
                                           v
                        [Interactive Incident Matrix + Timeline]
```

---

## 4. Threat Model & Security Controls

| Threat / Risk | Mitigating Control Implemented in CyberShield |
|---|---|
| **Arbitrary Network Scanning Abuse** | Target validation engine strictly enforces authorized lab scope (default: `127.0.0.1, localhost, ::1`). Public IP prefixes are rejected with `400 Bad Request`. |
| **Command Injection (RCE)** | All subprocess invocations use array argument lists (`shell=False`). User input is cleansed with strict regex checks before passing to any executable. |
| **Volumetric Network Flooding** | Denial-of-Service lab is implemented purely through synthetic mathematical queuing models and loopback simulations. Real distributed flooding functionality is completely prohibited. |
| **Sensitive Cryptographic Key Leakage** | RSA private keys and Vernam OTP pads are never persisted to database tables. Only key lengths, generation times, and public PEM certificates are recorded. |
| **Malicious File Uploads** | File uploads are restricted by extension (`.pcap`, `.cap`, `.pcapng`, `.log`), constrained by `MAX_CONTENT_LENGTH` (16 MB), secured via `secure_filename()`, and stored in isolated instance directories. |
| **Cross-Site Request Forgery (CSRF)** | State-changing web forms are protected via `Flask-WTF` CSRF tokens. AJAX endpoints are strictly validated for expected payloads. |
| **Clickjacking & MIME-Sniffing** | Global HTTP response headers enforce `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: strict-origin-when-cross-origin`. |
