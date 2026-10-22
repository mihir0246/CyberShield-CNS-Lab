import os
import time
from flask import Blueprint, render_template, request, jsonify, current_app, Response
from werkzeug.utils import secure_filename
from cybershield.services.packet_analysis.pcap_service import PcapService
from cybershield.extensions import db
from cybershield.models import ExperimentRun, PcapSummary

pcap_bp = Blueprint("pcap", __name__, url_prefix="/pcap")


@pcap_bp.route("/")
def pcap_lab():
    capture_info = PcapService.get_capture_mode_info()
    recent_pcaps = PcapSummary.query.order_by(PcapSummary.analyzed_at.desc()).limit(5).all()
    return render_template("pcap/pcap_lab.html", capture_info=capture_info, recent_pcaps=recent_pcaps)


@pcap_bp.route("/load_sample", methods=["POST"])
def load_sample():
    sample_path = os.path.join(current_app.config["BASE_DIR"], "samples", "sample_capture.pcap")
    if not os.path.exists(sample_path):
        return jsonify({"success": False, "error": "Sample PCAP file not found."}), 404

    t0 = time.perf_counter()
    try:
        parsed = PcapService.parse_pcap_file(sample_path)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        summary = PcapSummary(
            filename="sample_capture.pcap",
            packet_count=parsed["total_packets"],
            duration_seconds=parsed["duration_seconds"],
        )
        summary.set_protocols(parsed["protocol_distribution"])
        summary.set_top_talkers(parsed["top_talkers"])

        run = ExperimentRun(
            experiment_type="Packet Analysis",
            title=f"Sample PCAP Analysis ({parsed['total_packets']} packets)",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([summary, run])
        db.session.commit()

        return jsonify({"success": True, "data": parsed, "filename": "sample_capture.pcap"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@pcap_bp.route("/upload", methods=["POST"])
def upload_pcap():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected."}), 400

    filename = secure_filename(file.filename)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ("pcap", "cap", "pcapng"):
        return jsonify({"success": False, "error": f"Invalid extension '.{ext}'. Allowed: .pcap, .cap, .pcapng"}), 400

    upload_dir = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)
    save_path = os.path.join(upload_dir, f"{int(time.time())}_{filename}")

    t0 = time.perf_counter()
    try:
        file.save(save_path)
        parsed = PcapService.parse_pcap_file(save_path)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        summary = PcapSummary(
            filename=filename,
            packet_count=parsed["total_packets"],
            duration_seconds=parsed["duration_seconds"],
        )
        summary.set_protocols(parsed["protocol_distribution"])
        summary.set_top_talkers(parsed["top_talkers"])

        run = ExperimentRun(
            experiment_type="Packet Analysis",
            title=f"PCAP Upload Analysis ({filename}: {parsed['total_packets']} pkts)",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([summary, run])
        db.session.commit()

        return jsonify({"success": True, "data": parsed, "filename": filename})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@pcap_bp.route("/filter", methods=["POST"])
def filter_packets_route():
    data = request.get_json(silent=True) or {}
    packets = data.get("packets", [])
    protocol = data.get("protocol")
    ip_filter = data.get("ip")
    port_filter = data.get("port")
    flag_filter = data.get("flag")

    filtered = PcapService.filter_packets(
        packets,
        protocol=protocol,
        ip_filter=ip_filter,
        port_filter=port_filter,
        flag_filter=flag_filter,
    )
    return jsonify({"success": True, "filtered_packets": filtered, "count": len(filtered)})


@pcap_bp.route("/export_csv", methods=["POST"])
def export_csv_route():
    data = request.get_json(silent=True) or {}
    packets = data.get("packets", [])
    csv_text = PcapService.export_to_csv(packets)

    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=packet_analysis_export.csv"},
    )
