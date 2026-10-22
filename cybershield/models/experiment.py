from datetime import datetime, timezone
import json
from typing import Any
from cybershield.extensions import db


class ExperimentRun(db.Model):
    """General audit log of experiment executions."""
    __tablename__ = "experiment_runs"

    id = db.Column(db.Integer, primary_key=True)
    experiment_type = db.Column(db.String(64), nullable=False, index=True)
    title = db.Column(db.String(128), nullable=False)
    status = db.Column(db.String(32), default="SUCCESS")
    execution_time_ms = db.Column(db.Float, default=0.0)
    details_json = db.Column(db.Text, default="{}")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def __init__(
        self,
        experiment_type: str = "",
        title: str = "",
        status: str = "SUCCESS",
        execution_time_ms: float = 0.0,
        details_json: str = "{}",
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.experiment_type = experiment_type
        self.title = title
        self.status = status
        self.execution_time_ms = execution_time_ms
        self.details_json = details_json
        for k, v in kwargs.items():
            setattr(self, k, v)

    def set_details(self, data: dict):
        self.details_json = json.dumps(data)

    def get_details(self) -> dict:
        try:
            return json.loads(self.details_json) if self.details_json else {}
        except Exception:
            return {}

    def to_dict(self):
        return {
            "id": self.id,
            "experiment_type": self.experiment_type,
            "title": self.title,
            "status": self.status,
            "execution_time_ms": round(self.execution_time_ms, 3),
            "details": self.get_details(),
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.created_at else "",
        }


class CipherAudit(db.Model):
    """Metadata for classical & modern cipher operations without saving sensitive plaintexts."""
    __tablename__ = "cipher_audits"

    id = db.Column(db.Integer, primary_key=True)
    algorithm = db.Column(db.String(64), nullable=False)  # Caesar, Vernam, Rail Fence, Hill, RSA
    operation = db.Column(db.String(32), nullable=False)  # encrypt, decrypt
    input_length = db.Column(db.Integer, nullable=False)
    output_length = db.Column(db.Integer, nullable=False)
    key_params_json = db.Column(db.Text, default="{}")  # Key metadata e.g. matrix dim, shift, key size
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __init__(
        self,
        algorithm: str = "",
        operation: str = "",
        input_length: int = 0,
        output_length: int = 0,
        key_params_json: str = "{}",
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.algorithm = algorithm
        self.operation = operation
        self.input_length = input_length
        self.output_length = output_length
        self.key_params_json = key_params_json
        for k, v in kwargs.items():
            setattr(self, k, v)

    def set_key_params(self, params: dict):
        self.key_params_json = json.dumps(params)

    def get_key_params(self) -> dict:
        try:
            return json.loads(self.key_params_json) if self.key_params_json else {}
        except Exception:
            return {}

    def to_dict(self):
        return {
            "id": self.id,
            "algorithm": self.algorithm,
            "operation": self.operation,
            "input_length": self.input_length,
            "output_length": self.output_length,
            "key_params": self.get_key_params(),
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.created_at else "",
        }


class HashBenchmark(db.Model):
    """Stores benchmark metrics comparing MD5 and SHA-256."""
    __tablename__ = "hash_benchmarks"

    id = db.Column(db.Integer, primary_key=True)
    algorithm = db.Column(db.String(32), nullable=False)  # MD5, SHA-256
    input_type = db.Column(db.String(32), default="text")  # text, file, benchmark
    input_size_bytes = db.Column(db.Integer, nullable=False)
    trials = db.Column(db.Integer, default=1)
    avg_time_us = db.Column(db.Float, nullable=False)  # micro-seconds
    digest_preview = db.Column(db.String(64), nullable=False)
    digest_size_bits = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __init__(
        self,
        algorithm: str = "",
        input_type: str = "text",
        input_size_bytes: int = 0,
        trials: int = 1,
        avg_time_us: float = 0.0,
        digest_preview: str = "",
        digest_size_bits: int = 128,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.algorithm = algorithm
        self.input_type = input_type
        self.input_size_bytes = input_size_bytes
        self.trials = trials
        self.avg_time_us = avg_time_us
        self.digest_preview = digest_preview
        self.digest_size_bits = digest_size_bits
        for k, v in kwargs.items():
            setattr(self, k, v)

    def to_dict(self):
        return {
            "id": self.id,
            "algorithm": self.algorithm,
            "input_type": self.input_type,
            "input_size_bytes": self.input_size_bytes,
            "trials": self.trials,
            "avg_time_us": round(self.avg_time_us, 2),
            "digest_preview": self.digest_preview,
            "digest_size_bits": self.digest_size_bits,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.created_at else "",
        }


class PcapSummary(db.Model):
    """Summary of parsed PCAP captures."""
    __tablename__ = "pcap_summaries"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    packet_count = db.Column(db.Integer, default=0)
    protocols_json = db.Column(db.Text, default="{}")
    duration_seconds = db.Column(db.Float, default=0.0)
    top_talkers_json = db.Column(db.Text, default="[]")
    analyzed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __init__(
        self,
        filename: str = "",
        packet_count: int = 0,
        protocols_json: str = "{}",
        duration_seconds: float = 0.0,
        top_talkers_json: str = "[]",
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.filename = filename
        self.packet_count = packet_count
        self.protocols_json = protocols_json
        self.duration_seconds = duration_seconds
        self.top_talkers_json = top_talkers_json
        for k, v in kwargs.items():
            setattr(self, k, v)

    def set_protocols(self, data: dict):
        self.protocols_json = json.dumps(data)

    def get_protocols(self) -> dict:
        try:
            return json.loads(self.protocols_json) if self.protocols_json else {}
        except Exception:
            return {}

    def set_top_talkers(self, data: list):
        self.top_talkers_json = json.dumps(data)

    def get_top_talkers(self) -> list:
        try:
            return json.loads(self.top_talkers_json) if self.top_talkers_json else []
        except Exception:
            return []

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "packet_count": self.packet_count,
            "protocols": self.get_protocols(),
            "top_talkers": self.get_top_talkers(),
            "duration_seconds": round(self.duration_seconds, 2),
            "analyzed_at": self.analyzed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.analyzed_at else "",
        }


class ScanSummary(db.Model):
    """Authorized network scan execution summaries."""
    __tablename__ = "scan_summaries"

    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(128), nullable=False)
    scan_type = db.Column(db.String(64), nullable=False)
    command_executed = db.Column(db.String(256), nullable=False)
    ports_open_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(32), default="SUCCESS")
    ports_json = db.Column(db.Text, default="[]")
    raw_xml = db.Column(db.Text, default="")
    scanned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __init__(
        self,
        target: str = "",
        scan_type: str = "",
        command_executed: str = "",
        ports_open_count: int = 0,
        status: str = "SUCCESS",
        ports_json: str = "[]",
        raw_xml: str = "",
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.target = target
        self.scan_type = scan_type
        self.command_executed = command_executed
        self.ports_open_count = ports_open_count
        self.status = status
        self.ports_json = ports_json
        self.raw_xml = raw_xml
        for k, v in kwargs.items():
            setattr(self, k, v)

    def set_ports(self, data: list):
        self.ports_json = json.dumps(data)

    def get_ports(self) -> list:
        try:
            return json.loads(self.ports_json) if self.ports_json else []
        except Exception:
            return []

    def to_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "scan_type": self.scan_type,
            "command_executed": self.command_executed,
            "ports_open_count": self.ports_open_count,
            "status": self.status,
            "ports": self.get_ports(),
            "scanned_at": self.scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.scanned_at else "",
        }


class SnortAlertModel(db.Model):
    """Parsed Snort IDS alerts."""
    __tablename__ = "snort_alerts"

    id = db.Column(db.Integer, primary_key=True)
    timestamp_str = db.Column(db.String(64), nullable=False)
    generator_id = db.Column(db.String(16), default="1")
    sid = db.Column(db.String(32), default="")
    revision = db.Column(db.String(16), default="1")
    signature = db.Column(db.String(256), nullable=False)
    classification = db.Column(db.String(128), default="General Security Event")
    priority = db.Column(db.Integer, default=3)
    protocol = db.Column(db.String(16), default="TCP")
    src_ip = db.Column(db.String(64), default="")
    src_port = db.Column(db.Integer, default=0)
    dst_ip = db.Column(db.String(64), default="")
    dst_port = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __init__(
        self,
        timestamp_str: str = "",
        generator_id: str = "1",
        sid: str = "",
        revision: str = "1",
        signature: str = "",
        classification: str = "General Security Event",
        priority: int = 3,
        protocol: str = "TCP",
        src_ip: str = "",
        src_port: int = 0,
        dst_ip: str = "",
        dst_port: int = 0,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.timestamp_str = timestamp_str
        self.generator_id = generator_id
        self.sid = sid
        self.revision = revision
        self.signature = signature
        self.classification = classification
        self.priority = priority
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        for k, v in kwargs.items():
            setattr(self, k, v)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp_str,
            "sid": f"{self.generator_id}:{self.sid}:{self.revision}",
            "signature": self.signature,
            "classification": self.classification,
            "priority": self.priority,
            "protocol": self.protocol,
            "src": f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip,
            "dst": f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.created_at else "",
        }


class TrafficSimulationModel(db.Model):
    """Records DoS analysis and rate limiting simulation trials."""
    __tablename__ = "traffic_simulations"

    id = db.Column(db.Integer, primary_key=True)
    attack_type = db.Column(db.String(64), nullable=False)  # SYN Flood, UDP Flood, HTTP Request Flood
    baseline_rate = db.Column(db.Integer, nullable=False)   # packets / sec
    peak_rate = db.Column(db.Integer, nullable=False)
    duration_seconds = db.Column(db.Integer, nullable=False)
    mitigated = db.Column(db.Boolean, default=False)
    mitigation_strategy = db.Column(db.String(128), default="None")
    packets_simulated = db.Column(db.Integer, default=0)
    packets_dropped = db.Column(db.Integer, default=0)
    peak_latency_ms = db.Column(db.Float, default=0.0)
    anomaly_detected = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __init__(
        self,
        attack_type: str = "",
        baseline_rate: int = 0,
        peak_rate: int = 0,
        duration_seconds: int = 0,
        mitigated: bool = False,
        mitigation_strategy: str = "None",
        packets_simulated: int = 0,
        packets_dropped: int = 0,
        peak_latency_ms: float = 0.0,
        anomaly_detected: bool = True,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.attack_type = attack_type
        self.baseline_rate = baseline_rate
        self.peak_rate = peak_rate
        self.duration_seconds = duration_seconds
        self.mitigated = mitigated
        self.mitigation_strategy = mitigation_strategy
        self.packets_simulated = packets_simulated
        self.packets_dropped = packets_dropped
        self.peak_latency_ms = peak_latency_ms
        self.anomaly_detected = anomaly_detected
        for k, v in kwargs.items():
            setattr(self, k, v)

    def to_dict(self):
        return {
            "id": self.id,
            "attack_type": self.attack_type,
            "baseline_rate": self.baseline_rate,
            "peak_rate": self.peak_rate,
            "duration_seconds": self.duration_seconds,
            "mitigated": self.mitigated,
            "mitigation_strategy": self.mitigation_strategy,
            "packets_simulated": self.packets_simulated,
            "packets_dropped": self.packets_dropped,
            "peak_latency_ms": round(self.peak_latency_ms, 2),
            "anomaly_detected": self.anomaly_detected,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.created_at else "",
        }


class CorrelatedFindingModel(db.Model):
    """Unified security events correlated across experiments."""
    __tablename__ = "correlated_findings"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(256), nullable=False)
    severity = db.Column(db.String(32), default="MEDIUM")  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    primary_ip = db.Column(db.String(64), nullable=False)
    event_category = db.Column(db.String(64), nullable=False)
    evidence_json = db.Column(db.Text, default="[]")
    confidence_score = db.Column(db.Integer, default=80)
    correlated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __init__(
        self,
        title: str = "",
        severity: str = "MEDIUM",
        primary_ip: str = "",
        event_category: str = "",
        evidence_json: str = "[]",
        confidence_score: int = 80,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.title = title
        self.severity = severity
        self.primary_ip = primary_ip
        self.event_category = event_category
        self.evidence_json = evidence_json
        self.confidence_score = confidence_score
        for k, v in kwargs.items():
            setattr(self, k, v)

    def set_evidence(self, items: list):
        self.evidence_json = json.dumps(items)

    def get_evidence(self) -> list:
        try:
            return json.loads(self.evidence_json) if self.evidence_json else []
        except Exception:
            return []

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "primary_ip": self.primary_ip,
            "event_category": self.event_category,
            "evidence": self.get_evidence(),
            "confidence_score": self.confidence_score,
            "correlated_at": self.correlated_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.correlated_at else "",
        }
