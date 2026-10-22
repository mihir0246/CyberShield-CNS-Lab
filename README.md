# CyberShield: Integrated Cryptography and Network Security Laboratory

[![Python Version](https://img.shields.io/badge/Python-3.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.1-teal.svg)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/Tests-41%20Passed%20(100%25)-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/Security-Safe%20Execution%20Guardrails-navy.svg)]()
[![Database](https://img.shields.io/badge/Database-SQLite%20%2B%20SQLAlchemy-lightgrey.svg)]()

**CyberShield** is a complete, academically presentable full-stack cybersecurity laboratory platform designed for the second-year/third-year undergraduate engineering Cryptography and Network Security (CNS) practical syllabus.

Instead of running disconnected terminal scripts or static mockups, CyberShield unifies the entire practical curriculum into a single modern web application featuring mathematical algorithmic rigor, real cryptographic libraries (`cryptography`, `hashlib`), Scapy deep packet inspection, controlled Nmap vulnerability scanning with safe target whitelisting, non-disruptive synthetic Denial-of-Service traffic modeling, Snort IDS rule/alert ingestion, and cross-lab security event correlation.

---

## 1. Syllabus Experiments Mapping

| Exp # | Laboratory Practical | Implementation Details | Academic Features |
|---|---|---|---|
| **EXP 1** | **Classical Cryptographic Techniques** | Caesar (shift mod 26), Vernam One-Time Pad (byte-wise XOR), Rail Fence (transposition) | Character-level shift traces, bitwise XOR tables, zig-zag rail visualization. |
| **EXP 2** | **Hill Cipher** | 2x2 and 3x3 matrix multiplication modulo 26, modular inverse matrix via extended Euclidean algorithm | Invertibility validation (`gcd(det, 26) == 1`), non-invertible matrix rejection, vector math steps. |
| **EXP 3** | **RSA Cryptosystem** | RFC 8017 PKCS#1 v2.2 RSA-OAEP with SHA-256 and MGF1 | 1024, 2048, 3072-bit keygen, PEM export/import, key-size vs latency benchmark chart. |
| **EXP 4** | **Diffie–Hellman Key Exchange** | RFC 3526 MODP group parameter generation, HKDF-SHA256 (RFC 5869) key derivation | Dual-party Alice & Bob architecture, shared secret equality verification, textbook small-integer trace. |
| **EXP 5** | **MD5 Hashing & Integrity** | MD5 (RFC 1321) vs SHA-256 (FIPS 180-4) comparison, chunked file hashing, integrity checking | Multi-size benchmark suite (1 KB to 5 MB), collision security warnings (RFC 6151). |
| **EXP 6** | **Wireshark & Packet Analysis** | Scapy PCAP/PCAPNG parser, protocol demultiplexing, multi-criteria filtering, CSV export | Protocol distribution chart, top talkers, TCP flags dissection, promiscuous mode guide. |
| **EXP 7** | **Nmap Network Scanning** | Controlled subprocess wrapper, machine-readable XML parser, target whitelist guardrail | Connect (-sT), SYN (-sS), UDP (-sU), ping (-sn), service (-sV), sample report fallback. |
| **EXP 8** | **Controlled DoS Analysis** | Synthetic queuing model, latency curves, token-bucket defense, Hping3 study section | Non-disruptive rate-limiting simulation, threshold alerts, Hping3 flag study table. |
| **EXP 9** | **Snort IDS Log & Rule Analyzer** | Signature rule syntax deconstruction, fast-alert log parser, classification metrics, CSV export | Interactive rule breakdown (headers + options), sample log ingestion, sensor config guide. |
| **EXP 10** | **Integrated Event Correlation** | Multi-source telemetry fusion engine connecting PCAP wire frames, Snort alerts, and scan findings | Incident matrix, severity ratings (CRITICAL, HIGH, MEDIUM), confidence scores, timeline. |

---

## 2. Technology Stack

- **Backend:** Python 3.12+ (tested on Python 3.13), Flask 3.1.0, Flask-SQLAlchemy 3.1.1, Flask-WTF 1.2.2
- **Frontend:** Bootstrap 5.3.3, Bootstrap Icons 1.11.3, Chart.js 4.4.1, custom CSS design system
- **Database:** SQLite with SQLAlchemy ORM (zero sensitive plaintext or private key retention)
- **Cryptography:** Python standard library (`hashlib`, `secrets`) & `cryptography 44.0.2` (`asymmetric.rsa`, `dh`, `padding`, `hashes`, `kdf.hkdf`)
- **Packet Telemetry:** Scapy 2.6.1 (memory-efficient `PcapReader`)
- **Network Scanning:** Nmap CLI wrapper with strict parameter validation and XML parsing
- **Testing:** Automated pytest 8.3.4 test suite with 41 comprehensive tests
- **Documentation:** Complete academic deliverables in `docs/`

---

## 3. Project Directory Structure

```
cybershield/
├── .env.example                       # Sample environment configuration
├── .gitignore                         # Version control exclusions
├── pytest.ini                         # Pytest testpath and pythonpath configuration
├── requirements.txt                   # Pinned compatible dependencies
├── run.py                             # Primary local development server entrypoint
├── start.bat                          # One-click Windows startup script
├── start.sh                           # One-command Linux / macOS startup script
├── README.md                          # Comprehensive project documentation
├── cybershield/                       # Core application package
│   ├── __init__.py                    # Package initializer
│   ├── app.py                         # Flask Application Factory & security headers
│   ├── config.py                      # Development, Testing, and Production configs
│   ├── extensions.py                  # SQLAlchemy db and Flask-WTF csrf instances
│   ├── models/                        # Persistent ORM models
│   │   ├── __init__.py                # Model package exports
│   │   └── experiment.py              # ExperimentRun, CipherAudit, HashBenchmark, etc.
│   ├── routes/                        # Modular Blueprint controllers
│   │   ├── __init__.py                # Route exports
│   │   ├── main.py                    # Dashboard, tools diagnostics, health check, about
│   │   ├── ciphers.py                 # Caesar, Vernam OTP, Rail Fence endpoints
│   │   ├── hill.py                    # Hill cipher matrix validation, encrypt, decrypt
│   │   ├── rsa_routes.py              # RSA keygen, OAEP encryption, benchmark
│   │   ├── dh_routes.py               # Diffie-Hellman production & educational trace
│   │   ├── hash_routes.py             # MD5 vs SHA-256 text, file, and benchmark
│   │   ├── pcap_routes.py             # PCAP upload, sample loader, filtering, CSV export
│   │   ├── nmap_routes.py             # Nmap execution, target guardrails, XML parsing
│   │   ├── dos_routes.py              # Synthetic DoS simulation, token-bucket defense
│   │   ├── snort_routes.py            # Snort rule explainer, fast log ingestion, CSV
│   │   ├── correlation_routes.py      # Cross-lab multi-source correlation engine
│   │   ├── history_routes.py          # SQLite experiment history, JSON/CSV exports
│   │   └── docs_routes.py             # In-browser markdown manual viewer
│   ├── services/                      # Domain logic services
│   │   ├── ciphers/                   # Caesar, Vernam, Rail Fence, and Hill
│   │   ├── rsa/                       # RSA OAEP and benchmarking
│   │   ├── diffie_hellman/            # DH RFC 3526 exchange & HKDF derivation
│   │   ├── hashing/                   # HashService MD5 & SHA-256 suite
│   │   ├── packet_analysis/           # Scapy PCAP reader & sample generator
│   │   ├── network_scanning/          # Nmap subprocess runner & XML parser
│   │   ├── traffic_analysis/          # DoS mathematical simulator & spike analyzer
│   │   ├── snort/                     # Snort rule parser & fast alert reader
│   │   └── correlation/               # Multi-source temporal fusion engine
│   ├── static/                        # Frontend assets
│   │   ├── css/cybershield.css        # Dark navy cybersecurity theme
│   │   └── js/cybershield.js          # Unified AJAX, loading indicators, toasts
│   └── templates/                     # Jinja2 HTML templates
│       ├── base.html                  # Base layout with sidebar navigation & topbar
│       ├── dashboard.html             # Main dashboard overview & syllabus checklist
│       ├── tools.html                 # Tool diagnostics & system health
│       ├── history.html               # Experiment execution audit history
│       ├── about.html                 # Syllabus mapping & project details
│       ├── ciphers/                   # Classical & Hill cipher views
│       ├── rsa/                       # RSA cryptosystem view
│       ├── diffie_hellman/            # Diffie-Hellman view
│       ├── hashing/                   # Hash analysis & benchmark view
│       ├── pcap/                      # Wireshark & PCAP analysis view
│       ├── nmap/                      # Nmap network scanner view
│       ├── dos/                       # Controlled DoS & rate limiting view
│       ├── snort/                     # Snort IDS analyzer view
│       ├── correlation/               # Security event correlation view
│       ├── docs/                      # Manual index & document reader view
│       └── errors/                    # 404 and 500 error templates
├── docs/                              # Academic course deliverables
│   ├── project_report.md              # Comprehensive project report
│   ├── architecture.md                # System architecture & threat model
│   ├── installation_guide.md          # Multi-OS setup instructions
│   ├── practical_manual.md            # Detailed lab manual (Aim, Theory, Steps, Viva)
│   ├── testing_report.md              # Automated testing results (41 passed)
│   ├── security_considerations.md     # Safe execution policy & guardrails
│   └── viva_questions.md              # 30+ oral exam preparation Q&A
└── samples/                           # Authentic offline demonstration files
    ├── sample_capture.pcap            # Pre-generated Scapy capture with 13 packets
    ├── sample_nmap.xml                # Authentic Nmap XML scan output
    └── sample_snort.log               # Authentic Snort fast-alert IDS log
```

---

## 4. Setup and Execution Commands

### 4.1 Windows (PowerShell)
```powershell
# 1. Navigate to workspace
cd c:\Users\mihir\Desktop\CNS

# 2. Run the one-click startup batch script:
.\start.bat

# OR perform manual launch:
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

### 4.2 Linux / Ubuntu / WSL2
```bash
# 1. Run the one-command bash script:
chmod +x start.sh && ./start.sh

# OR perform manual launch:
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

### 4.3 Access Endpoints
- **Laboratory Web App:** `http://127.0.0.1:5000/`
- **Tool Diagnostics:** `http://127.0.0.1:5000/tools`
- **Health Check Endpoint:** `http://127.0.0.1:5000/health`
- **Laboratory Manual & Docs:** `http://127.0.0.1:5000/docs/`

---

## 5. Automated Test Verification

Run the complete test suite:
```powershell
.\.venv\Scripts\pytest -v
```

### Verified Test Results
```
============================= 41 passed in 4.95s ==============================
- tests/test_api_endpoints.py (6 passed)
- tests/test_ciphers.py (9 passed)
- tests/test_hill.py (5 passed)
- tests/test_rsa.py (4 passed)
- tests/test_dh.py (3 passed)
- tests/test_hashing.py (3 passed)
- tests/test_pcap.py (3 passed)
- tests/test_nmap.py (2 passed)
- tests/test_dos.py (2 passed)
- tests/test_snort.py (3 passed)
- tests/test_correlation.py (1 passed)
```

---

## 6. Faculty Demonstration Sequence

When presenting CyberShield to your project evaluator or laboratory faculty, follow this structured demonstration flow:

1. **Dashboard Overview (`/`):**
   - Highlight the 100% syllabus coverage checklist and KPI metrics.
   - Show how all experiment runs, cipher operations, and alerts are tracked in SQLite.
2. **Classical & Hill Ciphers (`/ciphers/` & `/hill/`):**
   - Demonstrate Caesar shift arithmetic steps.
   - Demonstrate Vernam OTP bitwise XOR breakdown and explain Shannon's perfect secrecy conditions.
   - Load the Valid 2x2 Hill Cipher preset, verify `det mod 26 = 9` and `det^-1 = 3`, then show encryption.
   - Click "Test Non-Invertible Key" to demonstrate how the matrix validator mathematically rejects non-invertible determinants (`gcd(det, 26) != 1`).
3. **Modern Asymmetric Cryptography (`/rsa/` & `/diffie-hellman/`):**
   - Generate an RSA-2048 keypair, encrypt with OAEP-SHA256, and decrypt with the private key.
   - Run the RSA key-size benchmark chart comparing 1024, 2048, and 3072 bit latencies.
   - Run the Diffie-Hellman exchange showing Alice and Bob deriving identical 256-bit keys via HKDF-SHA256, then switch to the textbook small-prime math proof.
4. **Data Integrity & Hash Benchmarks (`/hashing/`):**
   - Contrast MD5 vs. SHA-256 for text and uploaded files.
   - Execute the 5-trial benchmark across 1 KB to 5 MB payloads to explain RFC 6151 deprecation of MD5.
5. **Network Packet Dissection (`/pcap/`):**
   - Click "Load Sample Lab PCAP" to dissect 13 frames across HTTP, DNS, TCP, and ICMP.
   - Filter by TCP flag `SYN` to isolate port-probing traffic.
   - Open the "Promiscuous Mode Guide" to explain switched network CAM table behavior.
6. **Controlled Network Scanning (`/nmap/`):**
   - Demonstrate target whitelisting (show how scanning unauthorized external IPs is blocked).
   - Scan `127.0.0.1` or load the sample XML report to inspect open ports and service version banners.
7. **Controlled DoS Simulation (`/dos/`):**
   - Run the 15-second simulation with "Enforce Rate Limiting Defense" toggled ON (latency remains capped).
   - Turn rate limiting OFF and run again to show server latency degradation.
   - Review the Hping3 parameters study table.
8. **Snort IDS & Security Event Correlation (`/snort/` & `/correlation/`):**
   - In the Snort lab, click "Deconstruct Rule Syntax" to inspect rule headers and options.
   - Click "Ingest Sample Snort Alerts" to parse fast-alert signatures.
   - Navigate to `/correlation/` and click "Execute Cross-Lab Correlation Engine".
   - Show how the correlation engine connects the multi-port SYN probes from the PCAP with the Snort portscan alerts into a unified high-confidence incident finding.
9. **Lab Manual & Viva Preparation (`/docs/`):**
   - Open the built-in Practical Manual and Viva Voce questions in the browser to conclude the academic presentation.
