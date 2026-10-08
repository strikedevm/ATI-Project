# ==============================================================================
# Module: ssh_sandbox.py
# Description: Tri-OS Remote SSH Sandbox Orchestration Engine
# Supports: Linux, Windows (OpenSSH/PowerShell), macOS (Darwin)
# ==============================================================================
import os
import re
import time
import base64
import socket
import logging
from typing import Dict, Any, List, Optional, Tuple
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()

logger = logging.getLogger("ai_engine")

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    logger.warning("Paramiko not installed. SSH sandboxes will operate in simulation/offline mode.")

class SSHSandboxManager:
    """
    Orchestrates remote Tri-OS sandbox execution environments (Tier 2 provisioning).
    Supports Linux, Windows, and macOS hosts over SSH with automated OS fingerprinting,
    non-interactive script staging, and real-time output capture.
    """

    SUPPORTED_TARGETS = ["linux", "windows", "macos"]

    def __init__(self):
        pass

    def get_configured_sandboxes(self) -> Dict[str, Dict[str, Any]]:
        """
        Reads sandbox connection parameters from .env variables.
        Supports both named targets (SANDBOX_LINUX_*) and numbered targets (SANDBOX_1_*).
        """
        sandboxes = {
            "linux": {
                "name": "Linux Sandbox",
                "os_type": "linux",
                "host": os.getenv("SANDBOX_LINUX_HOST") or os.getenv("SANDBOX_1_HOST") or os.getenv("SANDBOX_1") or "",
                "port": int(os.getenv("SANDBOX_LINUX_PORT") or os.getenv("SANDBOX_1_PORT") or "22"),
                "username": os.getenv("SANDBOX_LINUX_USER") or os.getenv("SANDBOX_1_USER") or "",
                "password": os.getenv("SANDBOX_LINUX_PASS") or os.getenv("SANDBOX_1_PASS") or "",
                "key_path": os.getenv("SANDBOX_LINUX_KEY") or os.getenv("SANDBOX_1_KEY") or "",
                "custom_info": os.getenv("SANDBOX_LINUX_INFO") or os.getenv("SANDBOX_INFO_1") or "",
                "default_shell": "bash"
            },
            "windows": {
                "name": "Windows Sandbox",
                "os_type": "windows",
                "host": os.getenv("SANDBOX_WIN_HOST") or os.getenv("SANDBOX_WINDOWS_HOST") or os.getenv("SANDBOX_2_HOST") or os.getenv("SANDBOX_2") or "",
                "port": int(os.getenv("SANDBOX_WIN_PORT") or os.getenv("SANDBOX_WINDOWS_PORT") or os.getenv("SANDBOX_2_PORT") or "22"),
                "username": os.getenv("SANDBOX_WIN_USER") or os.getenv("SANDBOX_WINDOWS_USER") or os.getenv("SANDBOX_2_USER") or "",
                "password": os.getenv("SANDBOX_WIN_PASS") or os.getenv("SANDBOX_WINDOWS_PASS") or os.getenv("SANDBOX_2_PASS") or "",
                "key_path": os.getenv("SANDBOX_WIN_KEY") or os.getenv("SANDBOX_WINDOWS_KEY") or os.getenv("SANDBOX_2_KEY") or "",
                "custom_info": os.getenv("SANDBOX_WIN_INFO") or os.getenv("SANDBOX_INFO_2") or "",
                "default_shell": "powershell"
            },
            "macos": {
                "name": "macOS Sandbox",
                "os_type": "macos",
                "host": os.getenv("SANDBOX_MAC_HOST") or os.getenv("SANDBOX_MACOS_HOST") or os.getenv("SANDBOX_3_HOST") or os.getenv("SANDBOX_3") or "",
                "port": int(os.getenv("SANDBOX_MAC_PORT") or os.getenv("SANDBOX_MACOS_PORT") or os.getenv("SANDBOX_3_PORT") or "22"),
                "username": os.getenv("SANDBOX_MAC_USER") or os.getenv("SANDBOX_MACOS_USER") or os.getenv("SANDBOX_3_USER") or "",
                "password": os.getenv("SANDBOX_MAC_PASS") or os.getenv("SANDBOX_MACOS_PASS") or os.getenv("SANDBOX_3_PASS") or "",
                "key_path": os.getenv("SANDBOX_MAC_KEY") or os.getenv("SANDBOX_MACOS_KEY") or os.getenv("SANDBOX_3_KEY") or "",
                "custom_info": os.getenv("SANDBOX_MAC_INFO") or os.getenv("SANDBOX_INFO_3") or "",
                "default_shell": "zsh"
            }
        }

        # Tag configuration readiness
        for target, data in sandboxes.items():
            data["configured"] = bool(data["host"] and (data["password"] or data["key_path"]))

        return sandboxes

    def _create_ssh_client(self, target_cfg: Dict[str, Any], timeout: int = 8):
        """Creates an authenticated Paramiko SSHClient connection."""
        if not PARAMIKO_AVAILABLE:
            raise RuntimeError("Paramiko SSH library is not installed.")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs: Dict[str, Any] = {
            "hostname": target_cfg["host"],
            "port": target_cfg["port"],
            "username": target_cfg["username"],
            "timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout
        }

        key_path = target_cfg.get("key_path")
        if key_path and os.path.exists(key_path):
            kwargs["key_filename"] = key_path
        elif target_cfg.get("password"):
            kwargs["password"] = target_cfg["password"]

        client.connect(**kwargs)
        return client

    def test_connection(self, target_key: str, timeout: int = 8) -> Dict[str, Any]:
        """
        Tests SSH reachability and performs automated OS fingerprinting.
        If user supplied SANDBOX_INFO in .env, combines it with live probe.
        """
        sandboxes = self.get_configured_sandboxes()
        cfg = sandboxes.get(target_key.lower())
        if not cfg:
            return {"connected": False, "error": f"Unknown sandbox target '{target_key}'."}

        if not cfg["configured"]:
            return {
                "connected": False,
                "configured": False,
                "target": target_key,
                "error": f"Target '{cfg['name']}' not configured. Please set SANDBOX_{target_key.upper()}_HOST and credentials in .env."
            }

        start_time = time.time()
        client = None
        try:
            client = self._create_ssh_client(cfg, timeout=timeout)
            latency_ms = round((time.time() - start_time) * 1000, 1)

            # Perform OS Fingerprinting probe
            fingerprint = self._probe_os_fingerprint(client, cfg["os_type"])

            return {
                "connected": True,
                "configured": True,
                "target": target_key,
                "host": cfg["host"],
                "port": cfg["port"],
                "username": cfg["username"],
                "custom_info": cfg.get("custom_info"),
                "latency_ms": latency_ms,
                "fingerprint": fingerprint,
                "summary": f"{fingerprint.get('pretty_name', cfg['name'])} ({fingerprint.get('arch', 'x86_64')})"
            }

        except socket.timeout:
            return {"connected": False, "configured": True, "target": target_key, "error": "Connection timed out (host unreachable or port 22 firewalled)."}
        except paramiko.AuthenticationException:
            return {"connected": False, "configured": True, "target": target_key, "error": "SSH Authentication failed. Please verify username, password, or private key."}
        except Exception as e:
            return {"connected": False, "configured": True, "target": target_key, "error": str(e)}
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass

    def _probe_os_fingerprint(self, client, os_hint: str) -> Dict[str, Any]:
        """Executes non-invasive diagnostic commands over SSH to fingerprint the OS."""
        result = {
            "os_family": os_hint,
            "pretty_name": "Generic Host",
            "kernel": "Unknown",
            "arch": "Unknown",
            "python_version": "Not detected",
            "details": ""
        }

        try:
            if os_hint == "linux":
                # Uname and OS-Release probe
                _, stdout, _ = client.exec_command("uname -s -r -m && cat /etc/os-release 2>/dev/null", timeout=6)
                out = stdout.read().decode("utf-8", errors="ignore")
                lines = out.splitlines()
                if lines:
                    result["kernel"] = lines[0].strip()
                    parts = lines[0].strip().split()
                    if len(parts) >= 3:
                        result["arch"] = parts[-1]

                for line in lines[1:]:
                    if line.startswith("PRETTY_NAME="):
                        result["pretty_name"] = line.split("=", 1)[1].strip('"\'')
                    elif line.startswith("VERSION_ID="):
                        result["version_id"] = line.split("=", 1)[1].strip('"\'')

                # Python probe
                _, py_out, _ = client.exec_command("python3 --version 2>&1 || python --version 2>&1", timeout=4)
                py_ver = py_out.read().decode("utf-8", errors="ignore").strip()
                if py_ver:
                    result["python_version"] = py_ver

            elif os_hint == "windows":
                # PowerShell environment probe
                ps_cmd = 'powershell.exe -NoProfile -Command "[System.Environment]::OSVersion.VersionString; $env:PROCESSOR_ARCHITECTURE; python --version 2>$null"'
                _, stdout, _ = client.exec_command(ps_cmd, timeout=8)
                out = stdout.read().decode("utf-8", errors="ignore")
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                if len(lines) >= 1:
                    result["pretty_name"] = lines[0]
                    result["kernel"] = lines[0]
                if len(lines) >= 2:
                    result["arch"] = lines[1]
                if len(lines) >= 3:
                    result["python_version"] = lines[2]

            elif os_hint == "macos":
                # macOS sw_vers probe
                _, stdout, _ = client.exec_command("sw_vers && uname -m && python3 --version 2>&1", timeout=6)
                out = stdout.read().decode("utf-8", errors="ignore")
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                name = "macOS"
                ver = ""
                for line in lines:
                    if line.startswith("ProductName:"):
                        name = line.split(":", 1)[1].strip()
                    elif line.startswith("ProductVersion:"):
                        ver = line.split(":", 1)[1].strip()
                    elif any(a in line for a in ["arm64", "x86_64"]):
                        result["arch"] = line
                    elif "Python" in line:
                        result["python_version"] = line
                result["pretty_name"] = f"{name} {ver}".strip()

        except Exception as e:
            result["details"] = f"Fingerprint probe partial error: {e}"

        return result

    def execute_script(
        self,
        target_key: str,
        script_content: str,
        cve_id: str = "CVE-EXPERIMENT",
        timeout: int = 180
    ) -> Dict[str, Any]:
        """
        Uploads and executes a setup/reproduction script on the remote target sandbox.
        Automatically adapts to the target's operating system (bash, powershell, zsh).
        """
        sandboxes = self.get_configured_sandboxes()
        cfg = sandboxes.get(target_key.lower())
        if not cfg or not cfg["configured"]:
            return {
                "success": False,
                "error": f"Target sandbox '{target_key}' is not configured or reachable in .env.",
                "exit_code": -1
            }

        client = None
        start_time = time.time()
        cve_clean = cve_id.upper().replace("-", "_")

        try:
            client = self._create_ssh_client(cfg, timeout=10)
            os_type = cfg["os_type"]

            if os_type == "windows":
                # Execute on Windows using PowerShell
                remote_script_path = f"C:\\Windows\\Temp\\lab_setup_{cve_clean}.ps1"
                # Encode script in Base64 to bypass any quote or newline escaping issues
                encoded_bytes = base64.b64encode(script_content.encode("utf-16le")).decode("ascii")
                exec_cmd = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded_bytes}"

            else:
                # Linux or macOS
                remote_script_path = f"/tmp/lab_setup_{cve_clean}.sh"
                encoded_bytes = base64.b64encode(script_content.encode("utf-8")).decode("ascii")
                # Write decoded file on remote host and execute with bash
                exec_cmd = (
                    f"echo '{encoded_bytes}' | base64 -d > {remote_script_path} && "
                    f"chmod +x {remote_script_path} && "
                    f"bash {remote_script_path}"
                )

            logger.info(f"[SSH-SANDBOX] Executing lab script on {cfg['name']} ({cfg['host']})...")
            stdin, stdout, stderr = client.exec_command(exec_cmd, timeout=timeout)

            # Stream or buffer output
            out_bytes = stdout.read()
            err_bytes = stderr.read()
            exit_code = stdout.channel.recv_exit_status()

            stdout_text = out_bytes.decode("utf-8", errors="ignore")
            stderr_text = err_bytes.decode("utf-8", errors="ignore")
            duration = round(time.time() - start_time, 2)

            success = (exit_code == 0)
            return {
                "success": success,
                "target": target_key,
                "target_name": cfg["name"],
                "host": cfg["host"],
                "exit_code": exit_code,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "duration_sec": duration,
                "remote_path": remote_script_path
            }

        except socket.timeout:
            return {
                "success": False,
                "target": target_key,
                "error": f"Execution timed out after {timeout} seconds.",
                "exit_code": -124,
                "duration_sec": round(time.time() - start_time, 2)
            }
        except Exception as e:
            return {
                "success": False,
                "target": target_key,
                "error": f"SSH Execution Error: {str(e)}",
                "exit_code": -1,
                "duration_sec": round(time.time() - start_time, 2)
            }
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass

# Global singleton
ssh_sandbox = SSHSandboxManager()
