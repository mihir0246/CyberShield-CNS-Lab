import os
import time
from flask import Blueprint, render_template, request, jsonify, current_app
from cybershield.services.network_scanning.nmap_service import NmapService
from cybershield.extensions import db
from cybershield.models import ExperimentRun, ScanSummary

nmap_bp = Blueprint("nmap", __name__, url_prefix="/nmap")


@nmap_bp.route("/")
def nmap_lab():
    installation = NmapService.check_nmap_installation()
    allowed_targets = current_app.config.get("ALLOWED_SCAN_TARGETS", ["127.0.0.1", "localhost", "::1"])
    recent_scans = ScanSummary.query.order_by(ScanSummary.scanned_at.desc()).limit(5).all()

    return render_template(
        "nmap/nmap_lab.html",
        installation=installation,
        allowed_targets=allowed_targets,
        scan_types=NmapService.VALID_SCAN_TYPES,
        recent_scans=recent_scans,
    )


@nmap_bp.route("/scan", methods=["POST"])
def run_scan():
    data = request.get_json(silent=True) or request.form
    target = data.get("target", "127.0.0.1")
    scan_type = data.get("scan_type", "connect")
    ports = data.get("ports", "22,80,443,3306,5000,8080")

    allowed_targets = current_app.config.get("ALLOWED_SCAN_TARGETS", ["127.0.0.1", "localhost", "::1"])
    timeout = current_app.config.get("NMAP_TIMEOUT_SECONDS", 45)
    sample_path = os.path.join(current_app.config["BASE_DIR"], "samples", "sample_nmap.xml")

    t0 = time.perf_counter()
    try:
        report = NmapService.execute_scan(
            target=target,
            scan_type=scan_type,
            ports=ports,
            allowed_targets=allowed_targets,
            timeout_seconds=timeout,
            sample_fallback_path=sample_path,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Compute open ports count
        open_count = 0
        all_ports = []
        for h in report.get("hosts", []):
            for p in h.get("ports", []):
                all_ports.append(p)
                if p.get("state") == "open":
                    open_count += 1

        summary = ScanSummary(
            target=target,
            scan_type=scan_type,
            command_executed=report.get("command_executed", f"nmap {scan_type} {target}"),
            ports_open_count=open_count,
            status="SUCCESS",
        )
        summary.set_ports(all_ports)

        run = ExperimentRun(
            experiment_type="Network Scanning",
            title=f"Nmap {scan_type.upper()} Scan on {target} ({open_count} open ports)",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([summary, run])
        db.session.commit()

        return jsonify({"success": True, "data": report})
    except PermissionError as pe:
        return jsonify({"success": False, "error": str(pe), "requires_privilege": True}), 403
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except TimeoutError as te:
        return jsonify({"success": False, "error": str(te)}), 408
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@nmap_bp.route("/load_sample", methods=["POST"])
def load_sample():
    sample_path = os.path.join(current_app.config["BASE_DIR"], "samples", "sample_nmap.xml")
    try:
        report = NmapService.load_sample_report(sample_path)
        report["command_executed"] = "nmap -sV -p 22,80,443,3306,5000,8080 127.0.0.1 (DEMONSTRATION SAMPLE)"
        return jsonify({"success": True, "data": report})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
