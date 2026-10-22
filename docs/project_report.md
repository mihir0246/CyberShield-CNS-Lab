# CyberShield: Integrated Cryptography and Network Security Laboratory
## Comprehensive Engineering Project Report

---

### Abstract
In contemporary engineering curricula, Cryptography and Network Security (CNS) education frequently suffers from fragmentation between abstract theoretical mathematics and isolated command-line utility execution. Students often implement ciphers in disconnected terminal scripts while running packet analyzers or intrusion detection systems in separate proprietary tools without understanding their contextual intersections.

**CyberShield** resolves this educational gap by providing a unified, modular, and academically rigorous web-based laboratory platform. Built on Python 3.12+, Flask, SQLite/SQLAlchemy, and Bootstrap 5, CyberShield integrates the complete syllabus practical spectrum: Classical Ciphers (Caesar, Vernam One-Time Pad, Rail Fence), Matrix Hill Ciphers with modulo-26 invertibility checking, standard RSA-OAEP asymmetric encryption, Diffie-Hellman key exchange with HKDF key derivation, empirical MD5 vs. SHA-256 integrity benchmarking, Scapy-driven PCAP deep packet inspection, controlled Nmap vulnerability scanning with safe target whitelisting, non-disruptive synthetic Denial-of-Service traffic modeling with token-bucket defenses, Snort IDS rule/alert ingestion, and a unified security event correlation engine.

---

### 1. Objectives & Problem Statement
#### 1.1 Problem Statement
1. **Mathematical Abstraction Disconnect:** Cryptographic algorithms (such as modular matrix inversion in the Hill cipher or modular exponentiation in Diffie-Hellman) are taught on paper, but students lack interactive tools to inspect intermediate mathematical matrices and vector transformations in real time.
2. **Tool Fragmentation & Platform Inconsistencies:** Tools such as Nmap, Wireshark, and Snort require disparate OS configurations, elevated driver installations (Npcap/WinPcap), and separate interfaces, creating high barriers to entry for students on Windows or resource-constrained lab environments.
3. **Safety and Liability Hazards:** Unrestricted laboratory assignments asking students to explore port scanning or DoS tools (like Hping3) pose severe network abuse risks if deployed against unauthorized public systems.

#### 1.2 Project Objectives
- Unify all 9 core syllabus CNS practical experiments into a single, cohesive full-stack web application.
- Deliver strictly verified, production-grade cryptographic implementations using Python standard libraries and the `cryptography` package.
- Provide visual step-by-step arithmetic traces for modular arithmetic, vector-matrix multiplication, and bitwise XOR operations.
- Enforce strict ethical guardrails (e.g., target whitelisting, non-disruptive synthetic DoS modeling, conservative timeouts).
- Provide automated fallback demonstration data when native external CLI tools (Nmap, Snort) are not installed on host operating systems.
- Persist structured experiment metadata, benchmark latencies, and packet telemetry in an SQLite database.
- Offer automated cross-lab security event correlation linking wire telemetry, port enumeration, and IDS signatures.

---

### 2. Scope & Technical Architecture
#### 2.1 Scope
The project encompasses second-year and third-year undergraduate engineering curricula in Computer Science, Information Technology, and Cybersecurity, covering:
- Symmetric Classical Ciphers (Substitution & Transposition)
- Polygraphic Matrix Inversion Ciphers
- Asymmetric Public-Key Cryptography (RSA with OAEP padding)
- Key Negotiation Protocols (Diffie-Hellman with HKDF)
- Cryptographic Hash Functions & Integrity Verification (MD5 vs SHA-256)
- Packet Telemetry & Network Protocol Decoding (Scapy PCAP/PCAPNG)
- Network Scanning & Port Enumeration (Nmap controlled wrapper)
- Volumetric Denial-of-Service Analysis & Rate-Limiting Defenses
- Signature-Based Intrusion Detection (Snort rule syntax & log parsing)
- Cross-Domain Incident Correlation

#### 2.2 System Architecture
CyberShield utilizes a multi-tiered modular architecture:
- **Presentation Tier:** Responsive dark navy UI built with Bootstrap 5, Bootstrap Icons, Chart.js, and custom CSS variables.
- **Application & Routing Tier:** Flask Application Factory with 13 modular Blueprints (`ciphers`, `hill`, `rsa`, `dh`, `hashing`, `pcap`, `nmap`, `dos`, `snort`, `correlation`, `history`, `docs`, `main`).
- **Domain Service Tier:** Isolated business logic modules implementing algorithmic encryption, Scapy packet dissection, XML parsing, and correlation matrices.
- **Persistence Tier:** SQLite database managed via SQLAlchemy models with zero sensitive plaintext retention.

---

### 3. Database Schema
CyberShield enforces strict privacy and security principles: no plaintext secrets, private keys, or raw packet payloads are persistently stored.

1. **`experiment_runs`**:
   - `id` (INTEGER PRIMARY KEY)
   - `experiment_type` (VARCHAR 64)
   - `title` (VARCHAR 128)
   - `status` (VARCHAR 32)
   - `execution_time_ms` (FLOAT)
   - `details_json` (TEXT)
   - `created_at` (DATETIME UTC)

2. **`cipher_audits`**:
   - `id` (INTEGER PRIMARY KEY)
   - `algorithm` (VARCHAR 64)
   - `operation` (VARCHAR 32: encrypt/decrypt)
   - `input_length` (INTEGER)
   - `output_length` (INTEGER)
   - `key_params_json` (TEXT: shift, matrix dimensions, key bits)
   - `created_at` (DATETIME UTC)

3. **`hash_benchmarks`**:
   - `id` (INTEGER PRIMARY KEY)
   - `algorithm` (VARCHAR 32: MD5, SHA-256)
   - `input_type` (VARCHAR 32: text, file, benchmark)
   - `input_size_bytes` (INTEGER)
   - `trials` (INTEGER)
   - `avg_time_us` (FLOAT)
   - `digest_preview` (VARCHAR 64)
   - `digest_size_bits` (INTEGER: 128 or 256)
   - `created_at` (DATETIME UTC)

4. **`pcap_summaries`**:
   - `id` (INTEGER PRIMARY KEY)
   - `filename` (VARCHAR 256)
   - `packet_count` (INTEGER)
   - `protocols_json` (TEXT)
   - `duration_seconds` (FLOAT)
   - `top_talkers_json` (TEXT)
   - `analyzed_at` (DATETIME UTC)

5. **`scan_summaries`**:
   - `id` (INTEGER PRIMARY KEY)
   - `target` (VARCHAR 128)
   - `scan_type` (VARCHAR 64)
   - `command_executed` (VARCHAR 256)
   - `ports_open_count` (INTEGER)
   - `status` (VARCHAR 32)
   - `ports_json` (TEXT)
   - `scanned_at` (DATETIME UTC)

6. **`snort_alerts`**:
   - `id` (INTEGER PRIMARY KEY)
   - `timestamp_str` (VARCHAR 64)
   - `generator_id` (VARCHAR 16)
   - `sid` (VARCHAR 32)
   - `revision` (VARCHAR 16)
   - `signature` (VARCHAR 256)
   - `classification` (VARCHAR 128)
   - `priority` (INTEGER 1-4)
   - `protocol` (VARCHAR 16)
   - `src_ip` (VARCHAR 64)
   - `src_port` (INTEGER)
   - `dst_ip` (VARCHAR 64)
   - `dst_port` (INTEGER)
   - `created_at` (DATETIME UTC)

7. **`traffic_simulations`**:
   - `id` (INTEGER PRIMARY KEY)
   - `attack_type` (VARCHAR 64)
   - `baseline_rate` (INTEGER)
   - `peak_rate` (INTEGER)
   - `duration_seconds` (INTEGER)
   - `mitigated` (BOOLEAN)
   - `mitigation_strategy` (VARCHAR 128)
   - `packets_simulated` (INTEGER)
   - `packets_dropped` (INTEGER)
   - `peak_latency_ms` (FLOAT)
   - `anomaly_detected` (BOOLEAN)
   - `created_at` (DATETIME UTC)

8. **`correlated_findings`**:
   - `id` (INTEGER PRIMARY KEY)
   - `title` (VARCHAR 256)
   - `severity` (VARCHAR 32: CRITICAL, HIGH, MEDIUM, LOW)
   - `primary_ip` (VARCHAR 64)
   - `event_category` (VARCHAR 64)
   - `evidence_json` (TEXT)
   - `confidence_score` (INTEGER 0-100)
   - `correlated_at` (DATETIME UTC)

---

### 4. Educational Value & Syllabus Coverage
CyberShield directly maps to academic curricula specified by university accreditation boards (e.g., AICTE, ABET):
1. **Classical Foundations:** Teaches Shannon's criteria of confusion and diffusion.
2. **Mathematical Number Theory:** Enforces real modular matrix arithmetic, modular multiplicative inverse calculation via extended Euclidean algorithm, and modular exponentiation.
3. **Public Key Infrastructure:** Demonstrates RSA key generation scaling (O(k^3)) and the role of OAEP padding against Coppersmith and Bleichenbacher padding oracle attacks.
4. **Key Management:** Highlights Diffie-Hellman ephemeral negotiation and proves why unauthenticated DH is vulnerable to Man-in-the-Middle attacks.
5. **Data Integrity:** Directly addresses RFC 6151 deprecation of MD5 due to collision generation in polynomial time and contrasts it with 256-bit SHA-2.
6. **Network Defense in Depth:** Integrates wire packet capture, active port probing, defensive rate limiting, signature IDS matching, and centralized correlation.

---

### 5. Limitations & Future Scope
#### 5.1 Limitations
- Live packet capture in Windows requires administrative installation of Npcap; when uninstalled, Scapy functions strictly in offline PCAP parsing mode.
- Nmap raw socket scans (-sS, -sU, -O) require root on Linux or Administrator privileges on Windows.
- Real-time continuous Snort packet processing is decoupled into fast-alert log ingestion to avoid requiring a dedicated daemon during lab practical sessions.

#### 5.2 Future Scope
- Implementation of Elliptic Curve Cryptography (ECDH and ECDSA) alongside classic RSA.
- Post-Quantum Cryptography (PQC) integration (e.g., ML-KEM / Kyber and ML-DSA / Dilithium).
- WebSocket-based real-time network traffic streaming.
- Dockerized containerized lab environment for multi-node virtual attacker/victim setups.

---

### 6. Conclusion
CyberShield establishes a comprehensive benchmark for academic engineering laboratories. By combining production-grade algorithms, interactive step-by-step visual proofs, ethical defensive guardrails, and automated telemetry fusion, it empowers engineering students to master both theoretical cryptography and practical network security engineering.

---

### 7. References
1. Stallings, W. (2017). *Cryptography and Network Security: Principles and Practice* (7th ed.). Pearson.
2. Forouzan, B. A., & Mukhopadhyay, D. (2015). *Cryptography and Network Security* (3rd ed.). McGraw-Hill Education.
3. RFC 8017: *PKCS #1: RSA Cryptography Specifications Version 2.2*. IETF.
4. RFC 3526: *More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)*. IETF.
5. RFC 6151: *Updated Security Considerations for the MD5 Message-Digest and the HMAC-MD5 Algorithms*. IETF.
6. Lyon, G. (2009). *Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Vulnerability Scanning*. Insecure.com LLC.
7. Roesch, M. (1999). *Snort - Lightweight Intrusion Detection for Networks*. Proceedings of LISA '99: 13th Systems Administration Conference.
