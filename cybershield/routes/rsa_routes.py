import time
from flask import Blueprint, render_template, request, jsonify
from cybershield.services.rsa.rsa_service import RSAService
from cybershield.extensions import db
from cybershield.models import ExperimentRun, CipherAudit

rsa_bp = Blueprint("rsa", __name__, url_prefix="/rsa")


@rsa_bp.route("/")
def rsa_lab():
    return render_template("rsa/rsa_lab.html")


@rsa_bp.route("/generate_keys", methods=["POST"])
def generate_keys():
    data = request.get_json(silent=True) or request.form
    key_size = int(data.get("key_size", 2048))

    try:
        priv_key, pub_key, gen_ms = RSAService.generate_key_pair(key_size)
        pub_pem = RSAService.serialize_public_key(pub_key)
        priv_pem = RSAService.serialize_private_key(priv_key)
        details = RSAService.get_public_key_details(pub_key)

        run = ExperimentRun(
            experiment_type="RSA Cryptosystem",
            title=f"RSA-{key_size} Key Pair Generation",
            status="SUCCESS",
            execution_time_ms=gen_ms,
        )
        db.session.add(run)
        db.session.commit()

        return jsonify({
            "success": True,
            "key_size": key_size,
            "public_key_pem": pub_pem,
            "private_key_pem": priv_pem,
            "public_key_details": details,
            "generation_time_ms": round(gen_ms, 2),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@rsa_bp.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json(silent=True) or request.form
    plaintext = data.get("plaintext", "")
    pub_key_pem = data.get("public_key_pem", "")

    t0 = time.perf_counter()
    try:
        res = RSAService.encrypt(plaintext, pub_key_pem)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        audit = CipherAudit(
            algorithm="RSA-OAEP-SHA256",
            operation="encrypt",
            input_length=len(plaintext.encode("utf-8")),
            output_length=len(bytes.fromhex(res["ciphertext_hex"])),
        )
        audit.set_key_params({"key_size_bits": res["key_size"]})
        run = ExperimentRun(
            experiment_type="RSA Cryptosystem",
            title=f"RSA-{res['key_size']} OAEP Encryption",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([audit, run])
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@rsa_bp.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json(silent=True) or request.form
    ciphertext = data.get("ciphertext", "")
    priv_key_pem = data.get("private_key_pem", "")

    t0 = time.perf_counter()
    try:
        res = RSAService.decrypt(ciphertext, priv_key_pem)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        audit = CipherAudit(
            algorithm="RSA-OAEP-SHA256",
            operation="decrypt",
            input_length=len(ciphertext),
            output_length=res["recovered_length"],
        )
        audit.set_key_params({"key_size_bits": res["key_size"]})
        run = ExperimentRun(
            experiment_type="RSA Cryptosystem",
            title=f"RSA-{res['key_size']} OAEP Decryption",
            status="SUCCESS",
            execution_time_ms=elapsed_ms,
        )
        db.session.add_all([audit, run])
        db.session.commit()

        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@rsa_bp.route("/benchmark", methods=["GET"])
def run_benchmark():
    try:
        res = RSAService.run_benchmark()
        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
