import time
from flask import Blueprint, render_template, request, jsonify
from cybershield.services.diffie_hellman.dh_service import DHService
from cybershield.extensions import db
from cybershield.models import ExperimentRun

dh_bp = Blueprint("dh", __name__, url_prefix="/diffie-hellman")


@dh_bp.route("/")
def dh_lab():
    return render_template("diffie_hellman/dh_lab.html")


@dh_bp.route("/simulate_exchange", methods=["POST"])
def simulate_exchange():
    data = request.get_json(silent=True) or request.form
    key_size = int(data.get("key_size", 2048))

    t0 = time.perf_counter()
    try:
        res = DHService.run_cryptographic_exchange(key_size)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        run = ExperimentRun(
            experiment_type="Diffie-Hellman",
            title=f"DH Key Exchange & HKDF ({key_size}-bit MODP)",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add(run)
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@dh_bp.route("/educational_trace", methods=["POST"])
def educational_trace():
    data = request.get_json(silent=True) or request.form
    p = data.get("p", 23)
    g = data.get("g", 5)
    a = data.get("a", None)
    b = data.get("b", None)

    try:
        res = DHService.run_educational_math_trace(p, g, a, b)
        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
