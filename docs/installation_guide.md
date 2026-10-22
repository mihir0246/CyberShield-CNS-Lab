# CyberShield Installation & Environment Setup Guide

---

## 1. Prerequisites

- **Python:** Version 3.12 or newer (Tested and verified on Python 3.13)
- **Pip:** Version 24+
- **Operating System:**
  - **Windows:** Windows 10/11 (PowerShell or Command Prompt)
  - **Linux:** Ubuntu 22.04+ / Debian / Kali Linux / WSL2
  - **macOS:** macOS Sonoma or newer

---

## 2. Quick-Start Setup (Windows PowerShell)

Open PowerShell in the project directory:

```powershell
# 1. Clone or navigate to the project directory
cd c:\Users\mihir\Desktop\CNS

# 2. Create the Python virtual environment
python -m venv .venv

# 3. Activate the virtual environment
.\.venv\Scripts\Activate.ps1
# (If script execution is disabled, run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass)

# 4. Install all pinned dependencies
pip install -r requirements.txt

# 5. Initialize the environment configuration
Copy-Item .env.example .env

# 6. Launch the CyberShield Laboratory Server
python run.py
```

The application server will initialize SQLite database tables and start listening on:
- **Laboratory Web App:** `http://127.0.0.1:5000/`
- **Tool Diagnostics:** `http://127.0.0.1:5000/tools`
- **Health Check Endpoint:** `http://127.0.0.1:5000/health`
- **Lab Documentation:** `http://127.0.0.1:5000/docs/`

---

## 3. Quick-Start Setup (Linux / Ubuntu / WSL2)

Open a Bash terminal:

```bash
# 1. Navigate to the project root
cd /path/to/CNS

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Copy environment configuration
cp .env.example .env

# 5. Launch the application
python run.py
```

---

## 4. External Security Tools Installation (Optional)

CyberShield operates fully right out of the box using offline PCAP readers, synthetic DoS engines, and authentic fallback demonstration datasets. For live CLI scanning and sensor execution, install the external tools below:

### 4.1 Nmap (Network Scanner)
- **Windows:**
  1. Download the official GUI/CLI installer from: [https://nmap.org/download.html](https://nmap.org/download.html)
  2. During installation, select **Add Nmap to System PATH** and install the bundled Npcap driver.
  3. Verify installation in PowerShell: `nmap --version`
- **Linux / Ubuntu / WSL:**
  ```bash
  sudo apt-get update && sudo apt-get install -y nmap
  nmap --version
  ```

### 4.2 Snort (Intrusion Detection System)
- **Windows:**
  1. Download the Snort 2.9 Windows binary package from [https://www.snort.org/downloads](https://www.snort.org/downloads).
  2. Extract to `C:\Snort` and add `C:\Snort\bin` to your System PATH environment variables.
- **Linux / Ubuntu / WSL:**
  ```bash
  sudo apt-get update && sudo apt-get install -y snort
  snort -V
  ```

### 4.3 Wireshark & Npcap (Packet Dissector)
- **Windows:**
  1. Download Wireshark from [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)
  2. Ensure **Install Npcap in WinPcap API-compatible Mode** is checked.
- **Linux / Ubuntu / WSL:**
  ```bash
  sudo apt-get update && sudo apt-get install -y wireshark tshark
  ```

---

## 5. Automated Verification & Testing

Execute the automated pytest test suite to verify all core cipher engines, hashing benchmarks, PCAP dissection, Nmap XML parsers, and event correlation:

```powershell
# Windows
.\.venv\Scripts\pytest -v

# Linux / WSL
pytest -v
```

All tests execute with 100% deterministic local mocking, requiring zero external internet access or privileged drivers.
