import time
from flask import Blueprint, render_template, request, jsonify
from cybershield.services.ciphers.hill import HillCipher
from cybershield.extensions import db
from cybershield.models import ExperimentRun, CipherAudit

hill_bp = Blueprint("hill", __name__, url_prefix="/hill")


@hill_bp.route("/")
def hill_lab():
    return render_template("ciphers/hill.html")


@hill_bp.route("/validate_key", methods=["POST"])
def validate_key():
    data = request.get_json(silent=True) or request.form
    key_input = data.get("key_matrix")
    size = int(data.get("size", 2))

    try:
        matrix, inv_matrix, det_mod, det_inv = HillCipher.validate_and_parse_key(key_input, size)
        return jsonify({
            "success": True,
            "size": size,
            "matrix": matrix,
            "inverse_matrix": inv_matrix,
            "determinant_mod26": det_mod,
            "det_modular_inverse": det_inv,
            "invertible": True,
            "message": f"Valid {size}x{size} key matrix! Determinant mod 26 is {det_mod}, modular inverse is {det_inv}.",
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "invertible": False,
            "error": str(e),
        }), 400


@hill_bp.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json(silent=True) or request.form
    text = data.get("plaintext", "")
    key_input = data.get("key_matrix")
    size = int(data.get("size", 2))

    t0 = time.perf_counter()
    try:
        res = HillCipher.encrypt(text, key_input, size)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        audit = CipherAudit(
            algorithm=f"Hill Cipher ({size}x{size})",
            operation="encrypt",
            input_length=len(text),
            output_length=len(res["ciphertext"]),
        )
        audit.set_key_params({
            "dimension": size,
            "matrix": res["key_matrix"],
            "det_mod26": res["determinant_mod26"],
        })
        run = ExperimentRun(
            experiment_type="Hill Cipher",
            title=f"Hill Cipher Encryption ({size}x{size})",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([audit, run])
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@hill_bp.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json(silent=True) or request.form
    text = data.get("ciphertext", "")
    key_input = data.get("key_matrix")
    size = int(data.get("size", 2))

    t0 = time.perf_counter()
    try:
        res = HillCipher.decrypt(text, key_input, size)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        audit = CipherAudit(
            algorithm=f"Hill Cipher ({size}x{size})",
            operation="decrypt",
            input_length=len(text),
            output_length=len(res["recovered_plaintext"]),
        )
        audit.set_key_params({
            "dimension": size,
            "matrix": res["key_matrix"],
            "det_mod26": res["determinant_mod26"],
        })
        run = ExperimentRun(
            experiment_type="Hill Cipher",
            title=f"Hill Cipher Decryption ({size}x{size})",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([audit, run])
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
