# ==============================================================================
# Module: docker_manager.py
# Description: Active Container Lifecycle Management & Sandboxed Execution Engine
# ==============================================================================
import os
import re
import time
import socket
import logging
import subprocess
from typing import Dict, Any, List, Optional, Tuple, Callable

import requests
import docker
from database import db
from error_healer import healer
from lab_verifier import verifier
from error_registry import error_reg

logger = logging.getLogger("ai_engine")
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LABS_DIR = os.path.join(ROOT_DIR, "labs")
if not os.path.exists(LABS_DIR):
    os.makedirs(LABS_DIR, exist_ok=True)

class DockerManager:
    """
    Manages isolated container builds, local sandbox provisioning,
    lifecycle control, and automated self-healing execution loops.
    """

    def __init__(self):
        self._client = None

    def get_client(self) -> Optional[docker.DockerClient]:
        """Returns or initializes docker-py client instance."""
        try:
            if self._client is None:
                self._client = docker.from_env(timeout=4)
            # Test ping
            self._client.ping()
            return self._client
        except Exception:
            self._client = None
            return None

    def is_docker_available(self) -> Tuple[bool, str]:
        """
        Checks if the Docker daemon/engine is actively running.
        Returns: (is_available, status_message)
        """
        client = self.get_client()
        if client is not None:
            try:
                ver = client.version()
                v_str = ver.get("Version", "Unknown")
                return True, f"Docker Engine Active (v{v_str})"
            except Exception as e:
                return False, f"Docker ping failed: {str(e)[:100]}"

        # Fallback to CLI probe
        try:
            res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                return True, "Docker Engine Active (CLI Detected)"
        except Exception:
            pass

        return False, "Docker Engine Offline (Start Docker Desktop to deploy live containers)"

    def _get_workspace_path(self, cve_id: str) -> str:
        """Returns a sanitized path for a CVE's build environment."""
        cve_clean = cve_id.upper().replace(" ", "_").strip()
        path = os.path.join(LABS_DIR, cve_clean)
        os.makedirs(path, exist_ok=True)
        return path

    def find_free_host_port(self, desired_port: int) -> int:
        """Finds an open, unbound host port starting from desired_port."""
        if desired_port <= 0:
            desired_port = 8080

        # Test desired port first
        for port in range(desired_port, desired_port + 200):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("", port))
                    return port
                except OSError:
                    continue
        # Fallback: ask OS for an ephemeral free port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return s.getsockname()[1]

    # --------------------------------------------------------------------------
    # 1. AI BLUEPRINT BUILD & DEPLOY WITH SELF-HEALING LOOP
    # --------------------------------------------------------------------------
    def build_and_deploy_blueprint(
        self,
        cve_id: str,
        dockerfile_content: str,
        target_port: int = 80,
        auto_heal: bool = True,
        max_retries: int = 3,
        progress_cb: Optional[Callable[[str], None]] = None
    ) -> Dict[str, Any]:
        """
        Builds Docker image from blueprint with an automated closed-loop self-repair cycle.
        If build fails, captures stderr, feeds it to the ErrorHealer agent, patches the Dockerfile,
        and retries until success or max_retries is reached.
        """
        cve_clean = cve_id.upper().strip()
        tag_name = f"lab-{cve_clean.lower().replace('-', '_')}"
        container_name = f"lab_{cve_clean.lower().replace('-', '_')}"
        workspace = self._get_workspace_path(cve_clean)

        def log_step(msg: str):
            logger.info(f"[{cve_clean}] {msg}")
            if progress_cb:
                progress_cb(msg)

        log_step(f"Initializing build environment in: {os.path.basename(workspace)}")

        current_dockerfile = dockerfile_content.strip()
        repair_history: List[Dict[str, Any]] = []
        host_port = self.find_free_host_port(target_port)

        for attempt in range(1, max_retries + 1):
            dockerfile_path = os.path.join(workspace, "Dockerfile")
            with open(dockerfile_path, "w", encoding="utf-8") as f:
                f.write(current_dockerfile)

            log_step(f"Building Docker image '{tag_name}' (Attempt {attempt}/{max_retries})...")

            # Execute docker build via subprocess to capture full stdout/stderr
            build_cmd = ["docker", "build", "-t", f"{tag_name}:latest", workspace]
            try:
                proc = subprocess.run(
                    build_cmd,
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                build_stdout = proc.stdout or ""
                build_stderr = proc.stderr or ""
                combined_output = build_stdout + "\n" + build_stderr

                if proc.returncode == 0:
                    log_step("Docker image built successfully!")

                    # Persist novel repairs into Error Memory Registry for future instant 0-token reuse
                    if repair_history:
                        for rep in repair_history:
                            if not rep.get("cache_hit") and rep.get("error_log"):
                                error_reg.remember_solution(
                                    error_log=rep.get("error_log", ""),
                                    diagnosis=rep.get("diagnosis", ""),
                                    fix_description=rep.get("fix_description", ""),
                                    repaired_dockerfile=rep.get("repaired_dockerfile", ""),
                                    model_source=rep.get("model_used", "AI Cascade")
                                )
                                log_step(f"Persisted solution to Error Memory Registry: {rep.get('diagnosis', '')[:50]}...")

                    # Stop and remove existing container if running
                    self._stop_and_remove_raw(container_name)

                    # Run new container
                    log_step(f"Launching container '{container_name}' (port {host_port}:{target_port})...")
                    run_cmd = [
                        "docker", "run", "-d",
                        "--name", container_name,
                        "-p", f"{host_port}:{target_port}",
                        f"{tag_name}:latest"
                    ]
                    run_proc = subprocess.run(run_cmd, capture_output=True, text=True, timeout=30)
                    if run_proc.returncode != 0:
                        err_msg = run_proc.stderr or "Failed to run container."
                        log_step(f"Container launch failed: {err_msg}")
                        return {
                            "success": False,
                            "cve_id": cve_clean,
                            "error": f"Build succeeded but container run failed: {err_msg}",
                            "repair_history": repair_history
                        }

                    container_id = run_proc.stdout.strip()[:12]
                    log_step(f"Container running: {container_id} on http://localhost:{host_port}")

                    # Brief pause for service initialization
                    time.sleep(2)

                    # Initial health verification
                    audit = verifier.audit_container(cve_clean, host="localhost", port=host_port)

                    deploy_record = {
                        "cve_id": cve_clean,
                        "container_id": container_id,
                        "container_name": container_name,
                        "status": "running",
                        "deployment_type": "ai_blueprint",
                        "host_port": host_port,
                        "container_port": target_port,
                        "workspace_path": workspace,
                        "dockerfile_content": current_dockerfile,
                        "repair_history": repair_history,
                        "health_status": audit.get("health_status", "unknown"),
                        "audit_details": audit
                    }
                    db.save_lab_deployment(cve_clean, deploy_record)

                    return {
                        "success": True,
                        "cve_id": cve_clean,
                        "container_id": container_id,
                        "container_name": container_name,
                        "host_port": host_port,
                        "container_port": target_port,
                        "url": f"http://localhost:{host_port}",
                        "repair_count": len(repair_history),
                        "repair_history": repair_history,
                        "health_audit": audit,
                        "dockerfile_used": current_dockerfile
                    }

                else:
                    # Build failed
                    log_step(f"Build attempt {attempt} failed with exit code {proc.returncode}.")
                    if not auto_heal or attempt >= max_retries:
                        log_step("Max healing iterations reached or auto-heal disabled.")
                        return {
                            "success": False,
                            "cve_id": cve_clean,
                            "error": f"Docker build failed: {self._extract_summary_error(combined_output)}",
                            "full_log": combined_output,
                            "repair_history": repair_history,
                            "dockerfile_used": current_dockerfile
                        }

                    # Trigger Closed-Loop Self-Healing Agent
                    log_step(f"Activating LLM Self-Debugging Agent to analyze and patch Dockerfile...")
                    repair_result = healer.heal_dockerfile(
                        cve_id=cve_clean,
                        dockerfile_content=current_dockerfile,
                        error_log=combined_output,
                        attempt_number=attempt,
                        previous_repairs=repair_history
                    )

                    repair_history.append(repair_result)
                    log_step(f"AI Patch Applied: {repair_result.get('fix_description', 'Updated configuration')}")
                    current_dockerfile = repair_result.get("repaired_dockerfile", current_dockerfile)

            except subprocess.TimeoutExpired:
                log_step("Build command timed out after 180 seconds.")
                return {
                    "success": False,
                    "cve_id": cve_clean,
                    "error": "Docker build timed out after 3 minutes.",
                    "repair_history": repair_history
                }
            except Exception as e:
                log_step(f"System execution error: {str(e)}")
                return {
                    "success": False,
                    "cve_id": cve_clean,
                    "error": f"Execution error: {str(e)}",
                    "repair_history": repair_history
                }

        return {
            "success": False,
            "cve_id": cve_clean,
            "error": "Exhausted all repair attempts without a successful build.",
            "repair_history": repair_history
        }

    # --------------------------------------------------------------------------
    # 2. VULHUB LAB DEPLOYMENT
    # --------------------------------------------------------------------------
    def deploy_vulhub_lab(
        self,
        cve_id: str,
        docker_compose_url: str,
        progress_cb: Optional[Callable[[str], None]] = None
    ) -> Dict[str, Any]:
        """Downloads official Vulhub docker-compose.yml and spins up the environment."""
        cve_clean = cve_id.upper().strip()
        workspace = self._get_workspace_path(cve_clean)

        def log_step(msg: str):
            logger.info(f"[VULHUB-{cve_clean}] {msg}")
            if progress_cb:
                progress_cb(msg)

        log_step("Downloading verified Vulhub docker-compose.yml...")
        try:
            res = requests.get(docker_compose_url, timeout=12)
            if res.status_code != 200:
                return {"success": False, "error": f"Unable to download compose file (HTTP {res.status_code})"}

            compose_content = res.text
            compose_path = os.path.join(workspace, "docker-compose.yml")
            with open(compose_path, "w", encoding="utf-8") as f:
                f.write(compose_content)

            # Inspect ports from compose content
            port_matches = re.findall(r'["\']?(\d+):(\d+)["\']?', compose_content)
            host_port = int(port_matches[0][0]) if port_matches else 8080

            log_step("Executing 'docker compose up -d' in sandbox workspace...")
            proc = subprocess.run(
                ["docker", "compose", "-f", compose_path, "up", "-d"],
                capture_output=True,
                text=True,
                cwd=workspace,
                timeout=180
            )

            if proc.returncode != 0:
                err_msg = proc.stderr or proc.stdout
                return {"success": False, "error": f"docker compose up failed: {err_msg[:250]}"}

            log_step("Vulhub container environment is UP!")
            time.sleep(2)

            audit = verifier.audit_container(cve_clean, host="localhost", port=host_port)

            deploy_record = {
                "cve_id": cve_clean,
                "container_id": f"vulhub-{cve_clean.lower()}",
                "container_name": f"vulhub_{cve_clean.lower()}",
                "status": "running",
                "deployment_type": "vulhub",
                "host_port": host_port,
                "container_port": host_port,
                "workspace_path": workspace,
                "dockerfile_content": compose_content,
                "repair_history": [],
                "health_status": audit.get("health_status", "unknown"),
                "audit_details": audit
            }
            db.save_lab_deployment(cve_clean, deploy_record)

            return {
                "success": True,
                "cve_id": cve_clean,
                "deployment_type": "vulhub",
                "container_name": f"vulhub_{cve_clean.lower()}",
                "host_port": host_port,
                "url": f"http://localhost:{host_port}",
                "health_audit": audit
            }

        except Exception as e:
            return {"success": False, "error": f"Vulhub deployment failed: {str(e)}"}

    # --------------------------------------------------------------------------
    # 3. CONTAINER MANAGEMENT & STATUS
    # --------------------------------------------------------------------------
    def get_container_status(self, cve_id: str) -> Dict[str, Any]:
        """Inspects if the container for this CVE is currently running on the host."""
        cve_clean = cve_id.upper().strip()
        saved = db.get_lab_deployment(cve_clean)

        container_name = f"lab_{cve_clean.lower().replace('-', '_')}"
        if saved and saved.get("container_name"):
            container_name = saved["container_name"]

        is_running = False
        try:
            res = subprocess.run(
                ["docker", "ps", "--filter", f"name={container_name}", "--format", "{{.ID}}|{{.Status}}|{{.Ports}}"],
                capture_output=True,
                text=True,
                timeout=4
            )
            out = res.stdout.strip()
            if out:
                is_running = True
                parts = out.split("|")
                return {
                    "is_running": True,
                    "container_id": parts[0],
                    "status_text": parts[1] if len(parts) > 1 else "Up",
                    "ports_text": parts[2] if len(parts) > 2 else "Mapped",
                    "saved_record": saved
                }
        except Exception:
            pass

        return {
            "is_running": False,
            "status_text": "Stopped",
            "saved_record": saved
        }

    def stop_lab(self, cve_id: str) -> bool:
        """Stops and removes the running lab container or shuts down docker compose."""
        cve_clean = cve_id.upper().strip()
        saved = db.get_lab_deployment(cve_clean)

        container_name = f"lab_{cve_clean.lower().replace('-', '_')}"
        if saved and saved.get("container_name"):
            container_name = saved["container_name"]

        workspace = self._get_workspace_path(cve_clean)
        compose_file = os.path.join(workspace, "docker-compose.yml")

        stopped = False
        if os.path.exists(compose_file):
            try:
                subprocess.run(["docker", "compose", "-f", compose_file, "down"], capture_output=True, timeout=20)
                stopped = True
            except Exception:
                pass

        stopped = self._stop_and_remove_raw(container_name) or stopped

        if saved:
            saved["status"] = "stopped"
            saved["health_status"] = "offline"
            db.save_lab_deployment(cve_clean, saved)

        return stopped

    def get_container_logs(self, cve_id: str, tail: int = 80) -> str:
        """Retrieves stdout/stderr logs from the running lab container."""
        cve_clean = cve_id.upper().strip()
        saved = db.get_lab_deployment(cve_clean)
        container_name = f"lab_{cve_clean.lower().replace('-', '_')}"
        if saved and saved.get("container_name"):
            container_name = saved["container_name"]

        try:
            res = subprocess.run(
                ["docker", "logs", "--tail", str(tail), container_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            return (res.stdout or "") + (res.stderr or "")
        except Exception as e:
            return f"Failed to fetch logs: {str(e)}"

    def _stop_and_remove_raw(self, container_name: str) -> bool:
        """Helper to forcefully stop and delete a container by name."""
        try:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=10)
            return True
        except Exception:
            return False

    def _extract_summary_error(self, text: str) -> str:
        """Extracts the final error message line."""
        lines = [l.strip() for l in text.split("\n") if l.strip()]
        for l in reversed(lines):
            if any(k in l.lower() for k in ["error:", "failed", "returned a non-zero code", "not found"]):
                return l[:150]
        return lines[-1][:150] if lines else "Build failed"

# Global singleton
docker_mgr = DockerManager()
