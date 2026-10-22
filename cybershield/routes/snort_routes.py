import os
import time
from flask import Blueprint, render_template, request, jsonify, current_app, Response
from werkzeug.utils import secure_filename
from cybershield.services.snort.snort_service import SnortService
from cybershield.extensions import db
from cybershield.models import ExperimentRun, SnortAlertModel

snort_bp = Blueprint("snort", __name__, url_prefix="/snort")


@snort_bp.route("/")
def snort_lab():
    installation = SnortService.check_snort_installation()
    sample_rules = SnortService.SAMPLE_EDUCATIONAL_RULES
    recent_alerts = SnortAlertModel.query.order_by(SnortAlertModel.created_at.desc()).limit(15).all()

    return render_template(
        "snort/snort_lab.html",
        installation=installation,
        sample_rules=sample_rules,
        recent_alerts=recent_alerts,
    )


@snort_bp.route("/explain_rule", methods=["POST"])
def explain_rule_route():
    data = request.get_json(silent=True) or request.form
    rule_text = data.get("rule", "")
    try:
        explanation = SnortService.explain_rule(rule_text)
        return jsonify({"success": True, "data": explanation})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@snort_bp.route("/load_sample_log", methods=["POST"])
def load_sample_log():
    sample_path = os.path.join(current_app.config["BASE_DIR"], "samples", "sample_snort.log")
    if not os.path.exists(sample_path):
        return jsonify({"success": False, "error": "Sample Snort log file not found."}), 404

    t0 = time.perf_counter()
    try:
        res = SnortService.load_log_file(sample_path)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Persist alerts to DB
        for a in res["alerts"]:
            model = SnortAlertModel(
                timestamp_str=a["timestamp"],
                generator_id=a["gid"],
                sid=a["sid"],
                revision=a["rev"],
                signature=a["signature"],
                classification=a["classification"],
                priority=a["priority"],
                protocol=a["protocol"],
                src_ip=a["src_ip"],
                src_port=int(a["src_port"]) if a["src_port"].isdigit() else 0,
                dst_ip=a["dst_ip"],
                dst_port=int(a["dst_port"]) if a["dst_port"].isdigit() else 0,
            )
            db.session.add(model)

        run = ExperimentRun(
            experiment_type="Intrusion Detection",
            title=f"Sample Snort Alert Log Ingestion ({res['total_alerts']} alerts)",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add(run)
        db.session.commit()

        return jsonify({"success": True, "data": res, "is_sample_data": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@snort_bp.route("/upload_log", methods=["POST"])
def upload_log():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected."}), 400

    filename = secure_filename(file.filename)
    upload_dir = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)
    save_path = os.path.join(upload_dir, f"{int(time.time())}_{filename}")

    t0 = time.perf_counter()
    try:
        file.save(save_path)
        res = SnortService.load_log_file(save_path)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        for a in res["alerts"]:
            model = SnortAlertModel(
                timestamp_str=a["timestamp"],
                generator_id=a["gid"],
                sid=a["sid"],
                revision=a["rev"],
                signature=a["signature"],
                classification=a["classification"],
                priority=a["priority"],
                protocol=a["protocol"],
                src_ip=a["src_ip"],
                src_port=int(a["src_port"]) if a["src_port"].isdigit() else 0,
                dst_ip=a["dst_ip"],
                dst_port=int(a["dst_port"]) if a["dst_port"].isdigit() else 0,
            )
            db.session.add(model)

        run = ExperimentRun(
            experiment_type="Intrusion Detection",
            title=f"Snort Log Upload ({filename}: {res['total_alerts']} alerts)",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add(run)
        db.session.commit()

        return jsonify({"success": True, "data": res, "is_sample_data": False})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@snort_bp.route("/export_csv", methods=["POST"])
def export_csv_route():
    data = request.get_json(silent=True) or {}
    alerts = data.get("alerts", [])
    csv_text = SnortService.export_alerts_csv(alerts)

    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=snort_alerts_export.csv"},
    )
