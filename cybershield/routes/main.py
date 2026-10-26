from flask import Blueprint, render_template, jsonify, current_app
from cybershield.services.network_scanning.nmap_service import NmapService
from cybershield.services.snort.snort_service import SnortService
from cybershield.services.packet_analysis.pcap_service import PcapService
from cybershield.models import (
    ExperimentRun,
    CipherAudit,
    HashBenchmark,
    PcapSummary,
    ScanSummary,
    SnortAlertModel,
    TrafficSimulationModel,
    CorrelatedFindingModel,
)
import platform
import os
from pathlib import Path

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def dashboard():
    """Main CyberShield Cybersecurity Laboratory Dashboard."""
    # Compute laboratory statistics
    experiment_count = ExperimentRun.query.count()
    cipher_ops_count = CipherAudit.query.count()
    hash_bench_count = HashBenchmark.query.count()
    pcap_analyzed_count = PcapSummary.query.count()
    scans_count = ScanSummary.query.count()
    alerts_count = SnortAlertModel.query.count()
    sim_count = TrafficSimulationModel.query.count()
    findings_count = CorrelatedFindingModel.query.count()

    # Recent activities
    recent_runs = ExperimentRun.query.order_by(ExperimentRun.created_at.desc()).limit(8).all()

    # Tool status checks
    nmap_status = NmapService.check_nmap_installation()
    snort_status = SnortService.check_snort_installation()
    capture_info = PcapService.get_capture_mode_info()
    wireshark_status = PcapService.check_wireshark_installation()

    tools_summary = {
        "wireshark": {
            "name": "Wireshark & TShark",
            "available": wireshark_status.get("installed", False),
            "version": f"v{wireshark_status.get('version', '')}" if wireshark_status.get("installed") else "Not Installed",
            "status_badge": "bg-success" if wireshark_status.get("installed") else "bg-secondary",
        },
        "nmap": {
            "name": "Nmap Network Scanner",
            "available": nmap_status.get("installed", False),
            "version": nmap_status.get("version", "Not Installed"),
            "status_badge": "bg-success" if nmap_status.get("installed") else "bg-secondary",
        },
        "snort": {
            "name": "Snort IDS Sensor",
            "available": snort_status.get("installed", False),
            "version": snort_status.get("version", "Not Installed"),
            "status_badge": "bg-success" if snort_status.get("installed") else "bg-secondary",
        },
        "scapy": {
            "name": "Scapy Packet Engine",
            "available": True,
            "version": "2.6.1 (Npcap Active)" if wireshark_status.get("npcap_driver_active") else "2.6.1",
            "status_badge": "bg-success",
        },
        "cryptography": {
            "name": "Python Cryptography Engine",
            "available": True,
            "version": "44.0.2",
            "status_badge": "bg-success",
        },
    }

    # Syllabus completion checklist
    experiments_status = [
        {"num": 1, "title": "Classical Ciphers (Caesar, Vernam, Rail Fence)", "route": "ciphers.classical_lab", "status": "Ready", "done": cipher_ops_count > 0},
        {"num": 2, "title": "Hill Cipher (2x2 / 3x3 Modular Inversion)", "route": "hill.hill_lab", "status": "Ready", "done": cipher_ops_count > 0},
        {"num": 3, "title": "RSA Public-Key Cryptosystem & OAEP", "route": "rsa.rsa_lab", "status": "Ready", "done": False},
        {"num": 4, "title": "Diffie-Hellman Key Exchange & HKDF", "route": "dh.dh_lab", "status": "Ready", "done": False},
        {"num": 5, "title": "MD5 Hash Analysis & Integrity Verification", "route": "hashing.hash_lab", "status": "Ready", "done": hash_bench_count > 0},
        {"num": 6, "title": "Wireshark Packet Analysis & Scapy PCAP", "route": "pcap.pcap_lab", "status": "Ready", "done": pcap_analyzed_count > 0},
        {"num": 7, "title": "Nmap Authorized Network Scanner", "route": "nmap.nmap_lab", "status": "Ready", "done": scans_count > 0},
        {"num": 8, "title": "Controlled DoS Analysis & Rate Limiting", "route": "dos.dos_lab", "status": "Ready", "done": sim_count > 0},
        {"num": 9, "title": "Snort IDS Log & Rule Analyzer", "route": "snort.snort_lab", "status": "Ready", "done": alerts_count > 0},
        {"num": 10, "title": "Cross-Lab Security Event Correlation", "route": "correlation.correlation_lab", "status": "Ready", "done": findings_count > 0},
    ]

    completed_count = sum(1 for e in experiments_status if e["done"])
    completion_percent = int((completed_count / len(experiments_status)) * 100) if experiments_status else 0

    return render_template(
        "dashboard.html",
        experiment_count=experiment_count,
        cipher_ops_count=cipher_ops_count,
        hash_bench_count=hash_bench_count,
        pcap_analyzed_count=pcap_analyzed_count,
        scans_count=scans_count,
        alerts_count=alerts_count,
        sim_count=sim_count,
        findings_count=findings_count,
        recent_runs=recent_runs,
        tools_summary=tools_summary,
        experiments_status=experiments_status,
        completion_percent=completion_percent,
        completed_count=completed_count,
        os_info=f"{platform.system()} {platform.release()}",
    )


@main_bp.route("/tools")
def tools_page():
    """Tool availability and diagnostic status page."""
    nmap_status = NmapService.check_nmap_installation()
    snort_status = SnortService.check_snort_installation()
    capture_info = PcapService.get_capture_mode_info()
    wireshark_status = PcapService.check_wireshark_installation()

    return render_template(
        "tools.html",
        nmap=nmap_status,
        snort=snort_status,
        capture=capture_info,
        wireshark=wireshark_status,
        python_version=platform.python_version(),
        os_name=platform.platform(),
    )


@main_bp.route("/health")
def health_check():
    """JSON health check endpoint."""
    nmap_ok = NmapService.check_nmap_installation().get("installed", False)
    snort_ok = SnortService.check_snort_installation().get("installed", False)
    ws_ok = PcapService.check_wireshark_installation().get("installed", False)

    return jsonify({
        "status": "healthy",
        "app": "CyberShield: Integrated Cryptography and Network Security Laboratory",
        "version": "1.0.0",
        "system": {
            "os": platform.system(),
            "python": platform.python_version(),
        },
        "tools": {
            "nmap_installed": nmap_ok,
            "snort_installed": snort_ok,
            "wireshark_installed": ws_ok,
            "scapy_ready": True,
            "cryptography_ready": True,
        },
    })


@main_bp.route("/about")
def about_page():
    """Project documentation overview and syllabus specifications."""
    return render_template("about.html")
