import time
from flask import Blueprint, render_template, request, jsonify
from cybershield.services.ciphers.caesar import CaesarCipher
from cybershield.services.ciphers.vernam import VernamCipher
from cybershield.services.ciphers.railfence import RailFenceCipher
from cybershield.extensions import db
from cybershield.models import ExperimentRun, CipherAudit

ciphers_bp = Blueprint("ciphers", __name__, url_prefix="/ciphers")


@ciphers_bp.route("/")
def classical_lab():
    return render_template("ciphers/classical.html")


@ciphers_bp.route("/caesar/encrypt", methods=["POST"])
def caesar_encrypt():
    data = request.get_json(silent=True) or request.form
    text = data.get("plaintext", "")
    shift = data.get("shift", 3)

    t0 = time.perf_counter()
    try:
        res = CaesarCipher.encrypt(text, shift)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Log audit
        audit = CipherAudit(
            algorithm="Caesar Cipher",
            operation="encrypt",
            input_length=len(text),
            output_length=len(res["ciphertext"]),
        )
        audit.set_key_params({"shift": res["shift"]})
        run = ExperimentRun(
            experiment_type="Classical Ciphers",
            title=f"Caesar Encryption (Shift={res['shift']})",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([audit, run])
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@ciphers_bp.route("/caesar/decrypt", methods=["POST"])
def caesar_decrypt():
    data = request.get_json(silent=True) or request.form
    text = data.get("ciphertext", "")
    shift = data.get("shift", 3)

    t0 = time.perf_counter()
    try:
        res = CaesarCipher.decrypt(text, shift)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        audit = CipherAudit(
            algorithm="Caesar Cipher",
            operation="decrypt",
            input_length=len(text),
            output_length=len(res["plaintext"]),
        )
        audit.set_key_params({"shift": res["shift"]})
        run = ExperimentRun(
            experiment_type="Classical Ciphers",
            title=f"Caesar Decryption (Shift={res['shift']})",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([audit, run])
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@ciphers_bp.route("/vernam/encrypt", methods=["POST"])
def vernam_encrypt():
    data = request.get_json(silent=True) or request.form
    text = data.get("plaintext", "")
    key_hex = data.get("key_hex", None)
    if key_hex and not key_hex.strip():
        key_hex = None

    t0 = time.perf_counter()
    try:
        res = VernamCipher.encrypt(text, key_hex)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        audit = CipherAudit(
            algorithm="Vernam Cipher (OTP)",
            operation="encrypt",
            input_length=len(text.encode("utf-8")),
            output_length=len(bytes.fromhex(res["ciphertext_hex"])),
        )
        audit.set_key_params({"key_length_bytes": res["byte_length"]})
        run = ExperimentRun(
            experiment_type="Classical Ciphers",
            title="Vernam OTP Encryption",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([audit, run])
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@ciphers_bp.route("/vernam/decrypt", methods=["POST"])
def vernam_decrypt():
    data = request.get_json(silent=True) or request.form
    ciphertext_hex = data.get("ciphertext_hex", "")
    key_hex = data.get("key_hex", "")

    t0 = time.perf_counter()
    try:
        res = VernamCipher.decrypt(ciphertext_hex, key_hex)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        audit = CipherAudit(
            algorithm="Vernam Cipher (OTP)",
            operation="decrypt",
            input_length=res["byte_length"],
            output_length=len(res["plaintext"].encode("utf-8")),
        )
        audit.set_key_params({"key_length_bytes": res["byte_length"]})
        run = ExperimentRun(
            experiment_type="Classical Ciphers",
            title="Vernam OTP Decryption",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([audit, run])
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@ciphers_bp.route("/railfence/encrypt", methods=["POST"])
def railfence_encrypt():
    data = request.get_json(silent=True) or request.form
    text = data.get("plaintext", "")
    rails = data.get("rails", 3)

    t0 = time.perf_counter()
    try:
        res = RailFenceCipher.encrypt(text, rails)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        audit = CipherAudit(
            algorithm="Rail Fence Cipher",
            operation="encrypt",
            input_length=len(text),
            output_length=len(res["ciphertext"]),
        )
        audit.set_key_params({"rails": res["rails"]})
        run = ExperimentRun(
            experiment_type="Classical Ciphers",
            title=f"Rail Fence Encryption ({res['rails']} Rails)",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([audit, run])
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@ciphers_bp.route("/railfence/decrypt", methods=["POST"])
def railfence_decrypt():
    data = request.get_json(silent=True) or request.form
    text = data.get("ciphertext", "")
    rails = data.get("rails", 3)

    t0 = time.perf_counter()
    try:
        res = RailFenceCipher.decrypt(text, rails)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        audit = CipherAudit(
            algorithm="Rail Fence Cipher",
            operation="decrypt",
            input_length=len(text),
            output_length=len(res["plaintext"]),
        )
        audit.set_key_params({"rails": res["rails"]})
        run = ExperimentRun(
            experiment_type="Classical Ciphers",
            title=f"Rail Fence Decryption ({res['rails']} Rails)",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([audit, run])
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
