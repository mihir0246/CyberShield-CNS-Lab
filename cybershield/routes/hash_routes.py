import os
import time
from flask import Blueprint, render_template, request, jsonify, current_app
from werkzeug.utils import secure_filename
from cybershield.services.hashing.hash_service import HashService
from cybershield.extensions import db
from cybershield.models import ExperimentRun, HashBenchmark

hash_bp = Blueprint("hashing", __name__, url_prefix="/hashing")


@hash_bp.route("/")
def hash_lab():
    recent_benchmarks = HashBenchmark.query.order_by(HashBenchmark.created_at.desc()).limit(10).all()
    return render_template("hashing/hash_lab.html", benchmarks=recent_benchmarks)


@hash_bp.route("/text", methods=["POST"])
def hash_text_route():
    data = request.get_json(silent=True) or request.form
    text = data.get("text", "")

    t0 = time.perf_counter()
    try:
        res = HashService.hash_text(text)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        run = ExperimentRun(
            experiment_type="Hashing & Integrity",
            title="Text Hash Analysis (MD5 vs SHA-256)",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add(run)
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@hash_bp.route("/file", methods=["POST"])
def hash_file_route():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected."}), 400

    filename = secure_filename(file.filename)
    upload_dir = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)
    temp_path = os.path.join(upload_dir, f"hash_{int(time.time())}_{filename}")

    try:
        file.save(temp_path)
        res = HashService.hash_file(temp_path)

        # Cleanup file after hashing
        if os.path.exists(temp_path):
            os.remove(temp_path)

        run = ExperimentRun(
            experiment_type="Hashing & Integrity",
            title=f"File Integrity Verification ({filename})",
            status="SUCCESS",
            execution_time_ms=res["sha256"]["time_us"] / 1000.0,
        )
        db.session.add(run)
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"success": False, "error": str(e)}), 400


@hash_bp.route("/verify", methods=["POST"])
def verify_integrity_route():
    data = request.get_json(silent=True) or request.form
    d1 = data.get("digest1", "")
    d2 = data.get("digest2", "")
    try:
        res = HashService.verify_integrity(d1, d2)
        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@hash_bp.route("/benchmark", methods=["POST"])
def run_benchmark_route():
    data = request.get_json(silent=True) or request.form
    trials = int(data.get("trials", 5))

    t0 = time.perf_counter()
    try:
        res = HashService.run_benchmark_suite(trials)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Persist benchmark records
        for b in res["benchmark_data"]:
            record_md5 = HashBenchmark(
                algorithm="MD5",
                input_type="benchmark_payload",
                input_size_bytes=b["bytes"],
                trials=trials,
                avg_time_us=b["md5_avg_us"],
                digest_preview=b["md5_digest_preview"],
                digest_size_bits=128,
            )
            record_sha = HashBenchmark(
                algorithm="SHA-256",
                input_type="benchmark_payload",
                input_size_bytes=b["bytes"],
                trials=trials,
                avg_time_us=b["sha256_avg_us"],
                digest_preview=b["sha256_digest_preview"],
                digest_size_bits=256,
            )
            db.session.add_all([record_md5, record_sha])

        run = ExperimentRun(
            experiment_type="Hashing & Integrity",
            title=f"MD5 vs SHA-256 Benchmark Suite ({trials} trials)",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add(run)
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
