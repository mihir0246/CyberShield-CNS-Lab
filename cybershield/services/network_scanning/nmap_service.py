"""
Nmap Network Scanning Service
Controlled subprocess wrapper enforcing authorized target whitelists,
safe argument list construction, XML output parsing, and fallback sample reports.
"""
import shutil
import subprocess
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional


class NmapService:
    VALID_SCAN_TYPES = {
        "connect": {"flag": "-sT", "name": "TCP Connect Scan", "requires_root": False},
        "syn": {"flag": "-sS", "name": "TCP SYN Stealth Scan", "requires_root": True},
        "udp": {"flag": "-sU", "name": "UDP Port Scan", "requires_root": True},
        "ping": {"flag": "-sn", "name": "Ping Sweep / Host Discovery", "requires_root": False},
        "service": {"flag": "-sV", "name": "Service / Version Detection", "requires_root": False},
        "os": {"flag": "-O", "name": "OS Fingerprinting", "requires_root": True},
    }

    @staticmethod
    def get_nmap_path() -> Optional[str]:
        return shutil.which("nmap")

    @classmethod
    def check_nmap_installation(cls) -> Dict[str, Any]:
        """Detects whether Nmap is available on PATH and queries its version."""
        nmap_path = cls.get_nmap_path()
        if not nmap_path:
            return {
                "installed": False,
                "version": None,
                "binary_path": None,
                "instructions": [
                    "Windows: Download and run the official Nmap installer from https://nmap.org/download.html (check 'Add to PATH').",
                    "Linux / Ubuntu / WSL: Run `sudo apt-get update && sudo apt-get install -y nmap`.",
                    "macOS: Run `brew install nmap`.",
                ],
            }

        try:
            res = subprocess.run(
                [nmap_path, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            version_match = re.search(r"Nmap version ([0-9\.]+)", res.stdout)
            version = version_match.group(1) if version_match else res.stdout.splitlines()[0]
            return {
                "installed": True,
                "version": version,
                "binary_path": nmap_path,
                "raw": res.stdout.strip(),
            }
        except Exception as e:
            return {
                "installed": False,
                "error": str(e),
                "instructions": ["Ensure Nmap execution permissions are enabled."],
            }

    @classmethod
    def validate_target(cls, target: str, allowed_targets: List[str]) -> str:
        """Enforces that target is within the explicitly authorized lab scope."""
        target_clean = target.strip()
        if not target_clean:
            raise ValueError("Target address cannot be empty.")

        # Disallow shell metacharacters
        if re.search(r"[;&|`$><]", target_clean):
            raise ValueError("Security violation: Malicious characters detected in target string.")

        # Check against allowed targets list
        allowed_normalized = [t.lower().strip() for t in allowed_targets]
        if target_clean.lower() not in allowed_normalized:
            raise ValueError(
                f"Unauthorized Target: '{target_clean}' is not in the authorized lab targets list ({allowed_targets}). "
                f"Safety Policy: Scanning arbitrary public IP ranges is prohibited to prevent unauthorized network abuse."
            )

        return target_clean

    @classmethod
    def parse_nmap_xml(cls, xml_content: str) -> Dict[str, Any]:
        """Parses machine-readable Nmap XML into a structured dictionary."""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse Nmap XML output: {str(e)}")

        hosts_data = []
        for host in root.findall("host"):
            status_elem = host.find("status")
            status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

            addr_elem = host.find("address")
            ip = addr_elem.get("addr", "unknown") if addr_elem is not None else "unknown"

            hostnames = [
                h.get("name")
                for h in host.findall("hostnames/hostname")
                if h.get("name")
            ]

            ports_data = []
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    port_id = int(port.get("portid", 0))
                    protocol = port.get("protocol", "tcp")
                    state_elem = port.find("state")
                    state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                    reason = state_elem.get("reason", "") if state_elem is not None else ""

                    service_elem = port.find("service")
                    service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                    service_product = service_elem.get("product", "") if service_elem is not None else ""
                    service_version = service_elem.get("version", "") if service_elem is not None else ""

                    ports_data.append({
                        "port": port_id,
                        "protocol": protocol,
                        "state": state,
                        "reason": reason,
                        "service": service_name,
                        "product": service_product,
                        "version": service_version,
                    })

            hosts_data.append({
                "ip": ip,
                "status": status,
                "hostnames": hostnames,
                "ports": ports_data,
            })

        # Summary runstats
        runstats = root.find("runstats")
        summary_str = ""
        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                summary_str = finished.get("summary", "")

        return {
            "hosts": hosts_data,
            "summary": summary_str,
            "total_hosts": len(hosts_data),
        }

    @classmethod
    def load_sample_report(cls, sample_xml_path: str) -> Dict[str, Any]:
        """Loads and parses sample XML when Nmap is not installed or when mock report is requested."""
        p = Path(sample_xml_path)
        if not p.exists():
            raise FileNotFoundError(f"Sample Nmap XML not found at {sample_xml_path}")
        with open(p, "r", encoding="utf-8") as f:
            xml_content = f.read()

        parsed = cls.parse_nmap_xml(xml_content)
        parsed["is_sample_data"] = True
        parsed["notice"] = (
            "NOTICE: Nmap is not installed or live execution was bypassed. "
            "Displaying authentic demonstration scan results parsed from samples/sample_nmap.xml."
        )
        return parsed

    @classmethod
    def execute_scan(
        cls,
        target: str,
        scan_type: str,
        ports: str = "22,80,443,3306,5000,8080",
        allowed_targets: List[str] = None,
        timeout_seconds: int = 45,
        sample_fallback_path: str = "samples/sample_nmap.xml",
    ) -> Dict[str, Any]:
        """Executes a strictly bounded Nmap scan with timeout and safe argument construction."""
        if allowed_targets is None:
            allowed_targets = ["127.0.0.1", "localhost", "::1"]

        validated_target = cls.validate_target(target, allowed_targets)

        if scan_type not in cls.VALID_SCAN_TYPES:
            raise ValueError(f"Invalid scan type '{scan_type}'. Allowed: {list(cls.VALID_SCAN_TYPES.keys())}")

        nmap_path = cls.get_nmap_path()
        if not nmap_path:
            # Graceful fallback to sample report
            report = cls.load_sample_report(sample_fallback_path)
            report["command_executed"] = f"nmap {cls.VALID_SCAN_TYPES[scan_type]['flag']} -p {ports} {validated_target} (DEMO FALLBACK)"
            return report

        # Construct argument list safely (NO shell=True)
        scan_config = cls.VALID_SCAN_TYPES[scan_type]
        cmd = [nmap_path, "-oX", "-"]  # Output XML to stdout

        if scan_config["flag"]:
            cmd.append(scan_config["flag"])

        # Validate port specification
        ports_clean = ports.strip()
        if ports_clean and scan_type != "ping":
            if not re.match(r"^[0-9,\-]+$", ports_clean):
                raise ValueError("Port specification contains invalid characters. Use e.g. '80,443' or '1-1000'.")
            cmd.extend(["-p", ports_clean])

        cmd.append(validated_target)

        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_seconds,
            )
            if res.returncode != 0 and not res.stdout:
                raise RuntimeError(f"Nmap error (exit code {res.returncode}): {res.stderr.strip()}")

            parsed = cls.parse_nmap_xml(res.stdout)
            parsed["command_executed"] = " ".join(cmd)
            parsed["is_sample_data"] = False
            return parsed

        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Nmap scan exceeded maximum allowable timeout of {timeout_seconds} seconds.")
        except Exception as e:
            # If privileged scan failed due to permissions, return instructive message
            if "requires root" in str(e).lower() or "privileged" in str(e).lower():
                raise PermissionError(
                    f"Scan type '{scan_config['name']}' requires elevated / Administrator privileges. "
                    f"Try TCP Connect scan (-sT) or launch terminal with elevated permissions."
                )
            raise e
