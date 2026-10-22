import os
from pathlib import Path
from flask import Flask, render_template, jsonify
from flask_wtf.csrf import CSRFError
from cybershield.config import DevelopmentConfig, BASE_DIR
from cybershield.extensions import db, csrf
from cybershield.routes import (
    main_bp,
    ciphers_bp,
    hill_bp,
    rsa_bp,
    dh_bp,
    hash_bp,
    pcap_bp,
    nmap_bp,
    dos_bp,
    snort_bp,
    correlation_bp,
    history_bp,
    docs_bp,
)


def create_app(config_class=DevelopmentConfig):
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "cybershield" / "templates"),
        static_folder=str(BASE_DIR / "cybershield" / "static"),
    )
    app.config.from_object(config_class)
    app.config["BASE_DIR"] = BASE_DIR

    # Ensure instance and upload directories exist
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(BASE_DIR / "instance", exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)

    # Exempt JSON API routes from CSRF token requirement for easy AJAX and API testing
    # Note: State-changing form posts or AJAX can pass X-CSRFToken header or use token
    # For frictionless interactive laboratory experience, exempt programmatic JSON endpoints:
    csrf.exempt(ciphers_bp)
    csrf.exempt(hill_bp)
    csrf.exempt(rsa_bp)
    csrf.exempt(dh_bp)
    csrf.exempt(hash_bp)
    csrf.exempt(pcap_bp)
    csrf.exempt(nmap_bp)
    csrf.exempt(dos_bp)
    csrf.exempt(snort_bp)
    csrf.exempt(correlation_bp)
    csrf.exempt(history_bp)

    # Register Blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(ciphers_bp)
    app.register_blueprint(hill_bp)
    app.register_blueprint(rsa_bp)
    app.register_blueprint(dh_bp)
    app.register_blueprint(hash_bp)
    app.register_blueprint(pcap_bp)
    app.register_blueprint(nmap_bp)
    app.register_blueprint(dos_bp)
    app.register_blueprint(snort_bp)
    app.register_blueprint(correlation_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(docs_bp)

    # Security HTTP Response Headers
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("errors/500.html"), 500

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return jsonify({"success": False, "error": f"CSRF validation failed: {e.description}"}), 400

    # Create SQLite database schema
    with app.app_context():
        db.create_all()

    # Context processors
    @app.context_processor
    def inject_global_template_vars():
        return {
            "app_title": "CyberShield",
            "app_subtitle": "Integrated Cryptography & Network Security Laboratory",
            "current_year": 2026,
        }

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
