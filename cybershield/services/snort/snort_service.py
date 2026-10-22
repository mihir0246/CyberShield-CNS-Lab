"""
Snort Intrusion Detection System Service
Integrates Snort CLI detection, rule validation, educational rule explanation,
alert log parsing (fast and full format), filtering, and CSV export.
"""
import io
import csv
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional


class SnortService:
    SAMPLE_EDUCATIONAL_RULES = [
        {
            "id": "RULE-01",
            "name": "ICMP Ping Detection",
            "rule": 'alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"LAB ICMP Ping Echo Request Detected"; itype:8; sid:1000001; rev:1; classtype:attempted-recon; priority:3;)',
            "description": "Triggers an alert when an external host transmits an ICMP Echo Request (type 8, ping). Useful for detecting ping sweeps.",
        },
        {
            "id": "RULE-02",
            "name": "HTTP Directory Traversal Attempt",
            "rule": 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"LAB WEB-MISC Directory Traversal (../)"; content:"../"; nocase; sid:1000002; rev:1; classtype:web-application-attack; priority:1;)',
            "description": "Inspects incoming TCP payloads destined for HTTP port 80 for path traversal sequences ('../'). Priority 1 indicates critical severity.",
        },
        {
            "id": "RULE-03",
            "name": "SYN Port Scan Detection",
            "rule": 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LAB SCAN Stealth TCP SYN Scan Detected"; flags:S,12; sid:1000003; rev:1; classtype:attempted-recon; priority:2;)',
            "description": "Detects TCP segments with only the SYN flag set targeting unestablished sessions across multiple destination ports.",
        },
        {
            "id": "RULE-04",
            "name": "SQL Injection Keyword 'UNION SELECT'",
            "rule": 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"LAB SQL-INJECTION UNION SELECT Pattern"; content:"UNION"; nocase; content:"SELECT"; nocase; distance:1; sid:1000004; rev:1; classtype:web-application-attack; priority:1;)',
            "description": "Identifies classical SQL injection exploitation payloads attempting to extract unauthorized relational database tables.",
        },
    ]

    @staticmethod
    def get_snort_path() -> Optional[str]:
        return shutil.which("snort")

    @classmethod
    def check_snort_installation(cls) -> Dict[str, Any]:
        snort_path = cls.get_snort_path()
        if not snort_path:
            return {
                "installed": False,
                "version": None,
                "binary_path": None,
                "sensor_running": False,
                "instructions": [
                    "Windows: Download Snort 2.9.x from https://www.snort.org/downloads and install WinPcap/Npcap.",
                    "Ubuntu / Debian / WSL: Run `sudo apt-get update && sudo apt-get install -y snort`.",
                    "Verification: Execute `snort -V` in your shell to confirm binary availability.",
                ],
            }

        try:
            res = subprocess.run(
                [snort_path, "-V"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            v_match = re.search(r"Version\s+([0-9\.]+)", res.stdout)
            version = v_match.group(1) if v_match else res.stdout.splitlines()[0]
            return {
                "installed": True,
                "version": version,
                "binary_path": snort_path,
                "sensor_running": False,  # Snort daemon must be verified specifically
                "raw": res.stdout.strip(),
            }
        except Exception as e:
            return {
                "installed": False,
                "error": str(e),
                "sensor_running": False,
                "instructions": ["Ensure Snort execution permissions are enabled."],
            }

    @classmethod
    def explain_rule(cls, rule_text: str) -> Dict[str, Any]:
        """Deconstructs a Snort rule string into header and options components with explanation."""
        rule_clean = rule_text.strip()
        pattern = r"^(alert|log|pass|drop|reject|sdrop)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)$"
        match = re.match(pattern, rule_clean, re.IGNORECASE)

        if not match:
            return {
                "valid_syntax": False,
                "error": "Rule does not match standard Snort syntax: 'action proto src_ip src_port dir dst_ip dst_port (options)'",
            }

        action, proto, src_ip, src_port, direction, dst_ip, dst_port, raw_options = match.groups()

        # Parse options
        options_dict = {}
        opts = [o.strip() for o in raw_options.split(";") if o.strip()]
        for opt in opts:
            if ":" in opt:
                key, val = opt.split(":", 1)
                options_dict[key.strip()] = val.strip().strip('"')
            else:
                options_dict[opt.strip()] = True

        return {
            "valid_syntax": True,
            "rule": rule_clean,
            "header": {
                "action": action.upper(),
                "action_meaning": f"'{action.upper()}' defines what Snort does when traffic matches (e.g., generate alert, log packet, or drop session).",
                "protocol": proto.upper(),
                "src_ip": src_ip,
                "src_port": src_port,
                "direction": direction,
                "direction_meaning": "'->' denotes unidirectional traffic; '<>' denotes bidirectional monitoring.",
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            },
            "options": options_dict,
            "metadata": {
                "msg": options_dict.get("msg", "No description provided"),
                "sid": options_dict.get("sid", "N/A"),
                "rev": options_dict.get("rev", "1"),
                "classtype": options_dict.get("classtype", "unknown"),
                "priority": options_dict.get("priority", "3"),
            },
        }

    @classmethod
    def parse_fast_alert_log(cls, log_content: str) -> List[Dict[str, Any]]:
        """
        Parses Snort fast-alert format lines:
        MM/DD-hh:mm:ss.uuuuuu [**] [gid:sid:rev] Message [**] [Classification: Class] [Priority: Pri] {Proto} src:port -> dst:port
        """
        alerts = []
        # Regex matching Snort fast alert format
        line_pattern = re.compile(
            r"^(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.*?)\s+\[\*\*\]"
            r"(?:\s+\[Classification:\s+(.*?)\])?(?:\s+\[Priority:\s+(\d+)\])?\s+\{(\w+)\}\s+(\S+)\s+->\s+(\S+)"
        )

        for line_num, line in enumerate(log_content.splitlines(), start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            match = line_pattern.match(line_str)
            if match:
                ts, gid, sid, rev, msg, classification, priority, proto, src, dst = match.groups()

                src_ip, src_port = src, "-"
                if ":" in src:
                    src_ip, src_port = src.rsplit(":", 1)

                dst_ip, dst_port = dst, "-"
                if ":" in dst:
                    dst_ip, dst_port = dst.rsplit(":", 1)

                alerts.append({
                    "line": line_num,
                    "timestamp": ts,
                    "gid": gid,
                    "sid": sid,
                    "rev": rev,
                    "signature": msg,
                    "classification": classification or "General Alert",
                    "priority": int(priority) if priority else 3,
                    "protocol": proto.upper(),
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "raw": line_str,
                })

        return alerts

    @classmethod
    def load_log_file(cls, log_file_path: str) -> Dict[str, Any]:
        """Loads and parses a Snort alert log file."""
        p = Path(log_file_path)
        if not p.exists():
            raise FileNotFoundError(f"Snort log file not found: {log_file_path}")

        with open(p, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        alerts = cls.parse_fast_alert_log(content)

        # Classification and priority summaries
        class_summary: Dict[str, int] = {}
        priority_summary: Dict[int, int] = {}
        for a in alerts:
            c = a["classification"]
            p_val = a["priority"]
            class_summary[c] = class_summary.get(c, 0) + 1
            priority_summary[p_val] = priority_summary.get(p_val, 0) + 1

        return {
            "total_alerts": len(alerts),
            "alerts": alerts,
            "classification_summary": class_summary,
            "priority_summary": priority_summary,
            "filename": p.name,
        }

    @classmethod
    def export_alerts_csv(cls, alerts: List[Dict[str, Any]]) -> str:
        output = io.StringIO()
        fieldnames = [
            "timestamp",
            "sid",
            "signature",
            "classification",
            "priority",
            "protocol",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for a in alerts:
            writer.writerow(a)
        return output.getvalue()
