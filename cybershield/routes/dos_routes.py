import time
from flask import Blueprint, render_template, request, jsonify
from cybershield.services.traffic_analysis.dos_simulator import DosSimulator
from cybershield.extensions import db
from cybershield.models import ExperimentRun, TrafficSimulationModel

dos_bp = Blueprint("dos", __name__, url_prefix="/dos")


@dos_bp.route("/")
def dos_lab():
    recent_sims = TrafficSimulationModel.query.order_by(TrafficSimulationModel.created_at.desc()).limit(5).all()
    return render_template(
        "dos/dos_lab.html",
        hping3_guide=DosSimulator.HPING3_PARAMETERS_GUIDE,
        recent_sims=recent_sims,
    )


@dos_bp.route("/simulate", methods=["POST"])
def run_simulation():
    data = request.get_json(silent=True) or request.form
    attack_type = data.get("attack_type", "SYN Flood")
    baseline_rate = int(data.get("baseline_rate", 100))
    peak_rate = int(data.get("peak_rate", 2500))
    duration = int(data.get("duration", 15))
    apply_mitigation = str(data.get("apply_mitigation", "true")).lower() in ("true", "1", "yes")
    strategy = data.get("strategy", "Token Bucket Rate Limiting")
    threshold = int(data.get("threshold", 400))

    t0 = time.perf_counter()
    try:
        res = DosSimulator.run_simulation(
            attack_type=attack_type,
            baseline_rate=baseline_rate,
            peak_attack_rate=peak_rate,
            duration_seconds=duration,
            apply_mitigation=apply_mitigation,
            mitigation_strategy=strategy,
            rate_limit_threshold=threshold,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        model = TrafficSimulationModel(
            attack_type=attack_type,
            baseline_rate=baseline_rate,
            peak_rate=peak_rate,
            duration_seconds=duration,
            mitigated=apply_mitigation,
            mitigation_strategy=strategy if apply_mitigation else "None",
            packets_simulated=res["total_packets_simulated"],
            packets_dropped=res["total_packets_dropped"],
            peak_latency_ms=res["peak_latency_ms"],
            anomaly_detected=res["anomalies_detected_count"] > 0,
        )

        run = ExperimentRun(
            experiment_type="Traffic Analysis",
            title=f"DoS Simulation ({attack_type} - {'Mitigated' if apply_mitigation else 'Unmitigated'})",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([model, run])
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@dos_bp.route("/analyze_spikes", methods=["POST"])
def analyze_spikes():
    data = request.get_json(silent=True) or {}
    packets = data.get("packets", [])
    window = float(data.get("window_seconds", 1.0))

    try:
        res = DosSimulator.analyze_traffic_spikes(packets, window_seconds=window)
        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
