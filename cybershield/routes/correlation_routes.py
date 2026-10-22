import time
from flask import Blueprint, render_template, request, jsonify
from cybershield.services.correlation.event_correlator import EventCorrelator
from cybershield.extensions import db
from cybershield.models import (
    ExperimentRun,
    SnortAlertModel,
    PcapSummary,
    ScanSummary,
    TrafficSimulationModel,
    CorrelatedFindingModel,
)

correlation_bp = Blueprint("correlation", __name__, url_prefix="/correlation")


@correlation_bp.route("/")
def correlation_lab():
    recent_findings = CorrelatedFindingModel.query.order_by(CorrelatedFindingModel.correlated_at.desc()).limit(10).all()
    return render_template("correlation/correlation_lab.html", recent_findings=recent_findings)


@correlation_bp.route("/run", methods=["POST"])
def run_correlation():
    data = request.get_json(silent=True) or {}
    pcap_packets = data.get("pcap_packets", [])
    snort_alerts = data.get("snort_alerts", [])
    nmap_ports = data.get("nmap_ports", [])
    dos_anomalies = data.get("dos_anomalies", [])

    # If arrays not supplied in request payload, draw from persistent DB records!
    if not snort_alerts:
        db_alerts = SnortAlertModel.query.order_by(SnortAlertModel.id.desc()).limit(50).all()
        snort_alerts = [
            {
                "timestamp": a.timestamp_str,
                "sid": a.sid,
                "signature": a.signature,
                "classification": a.classification,
                "priority": a.priority,
                "protocol": a.protocol,
                "src_ip": a.src_ip,
                "src_port": str(a.src_port),
                "dst_ip": a.dst_ip,
                "dst_port": str(a.dst_port),
            }
            for a in db_alerts
        ]

    if not nmap_ports:
        last_scan = ScanSummary.query.order_by(ScanSummary.id.desc()).first()
        if last_scan:
            nmap_ports = last_scan.get_ports()

    t0 = time.perf_counter()
    try:
        res = EventCorrelator.correlate(
            pcap_packets=pcap_packets,
            snort_alerts=snort_alerts,
            nmap_ports=nmap_ports,
            dos_anomalies=dos_anomalies,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Persist correlated findings
        for f in res["findings"]:
            finding_model = CorrelatedFindingModel(
                title=f["title"],
                severity=f["severity"],
                primary_ip=f["primary_ip"],
                event_category=f["category"],
                confidence_score=f["confidence_score"],
            )
            finding_model.set_evidence(f["evidence"])
            db.session.add(finding_model)

        run = ExperimentRun(
            experiment_type="Event Correlation",
            title=f"Multi-Source Correlation ({res['total_correlated_incidents']} Incidents Identified)",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add(run)
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
