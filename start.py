"""Single-port launcher for JobHacker.

The FastAPI application serves both the API and the single-page frontend.
Run from the project root with: python start.py
"""
from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).parent.resolve()
HOST = "0.0.0.0"
PORT = 8000


def _lan_ip() -> str:
    """Return the LAN address that another device can use on the same network."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        return "YOUR-PC-IP"


if __name__ == "__main__":
    lan_ip = _lan_ip()
    print("=" * 62)
    print("  JobHacker — Fake Offer Letter & Phishing Inspector")
    print("=" * 62)
    print(f"[App]    Single origin: http://localhost:{PORT}")
    print(f"[Phone]  Same-Wi-Fi:  http://{lan_ip}:{PORT}")
    print("[API]    Available under the same origin at /api/v1")
    print("[Stop]   Press CTRL+C to stop")
    print("=" * 62)

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "backend.main:app",
        "--host",
        HOST,
        "--port",
        str(PORT),
    ]
    try:
        subprocess.run(cmd, cwd=str(ROOT_DIR), check=True)
    except KeyboardInterrupt:
        print("\n[JobHacker] Shutting down. Goodbye!")
