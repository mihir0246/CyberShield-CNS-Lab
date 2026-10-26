"""
CyberShield Entrypoint Script
Run this script to launch the local laboratory server:
    python run.py
"""
import os
import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from cybershield.app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("DEBUG", "true").lower() in ("true", "1", "yes")

    print("=" * 70)
    print("   [+] CYBERSHIELD: INTEGRATED CNS LABORATORY SERVER")
    print("=" * 70)
    print(f" * Laboratory URL:    http://{host}:{port}/")
    print(f" * Documentation:     http://{host}:{port}/docs/")
    print(f" * Tool Diagnostics:  http://{host}:{port}/tools")
    print(f" * System Health:     http://{host}:{port}/health")
    print("=" * 70)
    print(" Press CTRL+C to terminate the laboratory server.")
    print("=" * 70)

    app.run(host=host, port=port, debug=debug)
