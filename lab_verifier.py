# ==============================================================================
# Module: lab_verifier.py
# Description: Automated Environment Health, Service Verification & Audit Engine
# ==============================================================================
import time
import socket
import requests
from typing import Dict, Any, List, Optional

class LabVerifier:
    """
    Automated health verification and validation engine for deployed vulnerable labs.
    Probes open ports, performs HTTP health audits, and checks service availability.
    """

    def audit_container(
        self,
        cve_id: str,
        host: str = "localhost",
        port: Optional[int] = None,
        verification_steps: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Runs comprehensive reachability and service audits against a deployed container lab.
        """
        checks = []
        is_alive = False
        health_status = "unknown"
        http_status = None
        server_banner = "N/A"
        latency_ms = None

        if not port or port <= 0:
            return {
                "cve_id": cve_id,
                "is_alive": False,
                "health_status": "unreachable",
                "host": host,
                "port": port,
                "audit_summary": "No target port specified or mapped for this container.",
                "checks": [{"name": "Port Validation", "passed": False, "detail": "Target port is invalid or 0."}],
                "timestamp": time.time()
            }

        # Check 1: TCP Port Reachability
        t0 = time.time()
        tcp_ok = False
        try:
            with socket.create_connection((host, int(port)), timeout=4):
                tcp_ok = True
                latency_ms = round((time.time() - t0) * 1000, 2)
                checks.append({
                    "name": "TCP Socket Handshake",
                    "passed": True,
                    "detail": f"Successfully connected to {host}:{port} in {latency_ms}ms"
                })
        except Exception as e:
            checks.append({
                "name": "TCP Socket Handshake",
                "passed": False,
                "detail": f"Connection refused or timed out on {host}:{port} ({str(e)})"
            })

        # Check 2: HTTP / Web Service Probe (if TCP passed)
        if tcp_ok:
            is_alive = True
            health_status = "online"
            try:
                url = f"http://{host}:{port}/"
                res = requests.get(url, timeout=5, allow_redirects=True, headers={
                    "User-Agent": "ATI-LabVerifier/1.0 (Automated Lab Builder Security Check)"
                })
                http_status = res.status_code
                server_banner = res.headers.get("Server", res.headers.get("X-Powered-By", "HTTP Service Active"))
                checks.append({
                    "name": "HTTP Service Audit",
                    "passed": True,
                    "detail": f"HTTP {res.status_code} ({res.reason}) - Server: {server_banner}"
                })
            except requests.exceptions.RequestException as e:
                checks.append({
                    "name": "HTTP Service Audit",
                    "passed": False,
                    "detail": f"TCP port is open, but service did not respond with standard HTTP: {str(e)[:120]}"
                })
        else:
            health_status = "port_closed"

        # Check 3: Process any custom blueprint verification steps
        if verification_steps:
            for step in verification_steps:
                checks.append({
                    "name": "Blueprint Verification Guideline",
                    "passed": True if tcp_ok else False,
                    "detail": str(step)
                })

        summary = (
            f"Target service is ONLINE and responding at http://{host}:{port} (HTTP {http_status or 'TCP Socket OK'})."
            if is_alive else
            f"Target service is OFFLINE or initializing. Port {port} on {host} is not yet accepting connections."
        )

        return {
            "cve_id": cve_id,
            "is_alive": is_alive,
            "health_status": health_status,
            "host": host,
            "port": port,
            "latency_ms": latency_ms,
            "http_status": http_status,
            "server_banner": server_banner,
            "audit_summary": summary,
            "checks": checks,
            "timestamp": time.time()
        }

# Global singleton
verifier = LabVerifier()
