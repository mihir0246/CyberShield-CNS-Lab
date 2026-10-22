import io
import csv
import json
from flask import Blueprint, render_template, request, jsonify, Response
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
from cybershield.extensions import db

history_bp = Blueprint("history", __name__, url_prefix="/history")


@history_bp.route("/")
def history_page():
    exp_type = request.args.get("type")
    query = ExperimentRun.query.order_by(ExperimentRun.created_at.desc())
    if exp_type:
        query = query.filter_by(experiment_type=exp_type)
    runs = query.limit(100).all()

    types = db.session.query(ExperimentRun.experiment_type).distinct().all()
    distinct_types = [t[0] for t in types if t[0]]

    return render_template("history.html", runs=runs, distinct_types=distinct_types, selected_type=exp_type)


@history_bp.route("/export/json")
def export_json():
    runs = ExperimentRun.query.order_by(ExperimentRun.created_at.desc()).all()
    data = [r.to_dict() for r in runs]
    json_str = json.dumps(data, indent=2)
    return Response(
        json_str,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=cybershield_experiment_history.json"},
    )


@history_bp.route("/export/csv")
def export_csv():
    runs = ExperimentRun.query.order_by(ExperimentRun.created_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Experiment Type", "Title", "Status", "Execution Time (ms)", "Created At"])
    for r in runs:
        writer.writerow([
            r.id,
            r.experiment_type,
            r.title,
            r.status,
            round(r.execution_time_ms, 3),
            r.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if r.created_at else "",
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=cybershield_experiment_history.csv"},
    )


@history_bp.route("/clear", methods=["POST"])
def clear_history():
    try:
        ExperimentRun.query.delete()
        CipherAudit.query.delete()
        HashBenchmark.query.delete()
        PcapSummary.query.delete()
        ScanSummary.query.delete()
        SnortAlertModel.query.delete()
        TrafficSimulationModel.query.delete()
        CorrelatedFindingModel.query.delete()
        db.session.commit()
        return jsonify({"success": True, "message": "Experiment history successfully cleared."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
