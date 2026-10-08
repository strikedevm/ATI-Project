# ==============================================================================
# Module: error_registry.py
# Description: Case-Based Reasoning (CBR) Memory & Error Resolution Registry
# Inspired by: AutoAttacker Experience Manager & Reflexion Long-Term Memory
# ==============================================================================
import re
import hashlib
from typing import Dict, Any, Optional, Tuple, List
from database import db

class ErrorRegistry:
    """
    Experience memory cache for container build and script execution errors.
    Allows instant (<1ms) application of previously solved errors without calling LLMs.
    """

    # Pre-defined known error patterns and their deterministic signatures
    KNOWN_SIGNATURE_PATTERNS = [
        (
            r"(?:404\s+Not\s+Found|failed\s+to\s+fetch).*?(?:deb\.debian\.org|security\.debian\.org)",
            "APT_DEBIAN_ARCHIVE_404",
            "repository_404",
            "Debian release is End-of-Life (EOL), causing standard mirrors to return 404.",
            "RUN sed -i 's/deb.debian.org/archive.debian.org/g' /etc/apt/sources.list && \\\n"
            "    sed -i 's/security.debian.org/archive.debian.org/g' /etc/apt/sources.list && \\\n"
            "    echo 'Acquire::Check-Valid-Until \"false\";' > /etc/apt/apt.conf.d/99no-check-valid-until\n"
        ),
        (
            r"debconf:\s+unable\s+to\s+initialize\s+frontend:\s+Dialog",
            "DEBIAN_FRONTEND_INTERACTIVE_HANG",
            "syntax_error",
            "apt-get stalled waiting for interactive terminal prompt.",
            "ENV DEBIAN_FRONTEND=noninteractive\n"
        ),
        (
            r"error:\s+externally-managed-environment",
            "PIP_PEP668_EXTERNALLY_MANAGED",
            "dependency_conflict",
            "Modern Python environments block global pip installs under PEP 668.",
            "RUN pip install --break-system-packages "
        ),
        (
            r"Cannot\s+find\s+a\s+valid\s+baseurl\s+for\s+repo:\s+base.*?centos",
            "YUM_CENTOS_VAULT_404",
            "repository_404",
            "CentOS release repositories have moved to vault.centos.org.",
            "RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && \\\n"
            "    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*\n"
        ),
        (
            r"gpg:\s+keyserver\s+receive\s+failed:\s+No\s+name",
            "GPG_KEYSERVER_TIMEOUT",
            "network_timeout",
            "GPG keyserver timed out or port 11371 is blocked.",
            "RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys "
        )
    ]

    def __init__(self):
        self._seed_default_rules()

    def _seed_default_rules(self):
        """Pre-seeds standard high-frequency Docker fixes into memory."""
        try:
            for pat, sig, cat, diag, patch in self.KNOWN_SIGNATURE_PATTERNS:
                existing = db.lookup_error_solution(sig)
                if not existing:
                    db.save_error_solution(
                        error_signature=sig,
                        error_category=cat,
                        sample_error_text=f"Pattern: {pat}",
                        fix_description=diag,
                        patch_instructions=patch,
                        patch_type="dockerfile_patch",
                        model_source="Verified Registry"
                    )
        except Exception:
            pass

    def extract_signature(self, error_text: str) -> Tuple[str, str]:
        """
        Normalizes error text into a deterministic signature and category.
        Returns: (error_signature, error_category)
        """
        if not error_text:
            return "UNKNOWN_EMPTY_ERROR", "unknown"

        # Check known regex patterns first
        for pat, sig, cat, _, _ in self.KNOWN_SIGNATURE_PATTERNS:
            if re.search(pat, error_text, re.IGNORECASE):
                return sig, cat

        # Dynamic fingerprinting: hash normalized error lines
        lines = [l.strip().lower() for l in error_text.splitlines() if l.strip()]
        error_lines = [l for l in lines if any(k in l for k in ["error:", "failed", "fatal:", "e:", "returned a non-zero code"])]
        key_content = " ".join(error_lines[-3:]) if error_lines else " ".join(lines[-2:])
        # Strip paths and volatile digits
        sanitized = re.sub(r"/[\w\.-]+", "", key_content)
        sanitized = re.sub(r"\b\d+\b", "", sanitized).strip()
        h = hashlib.sha256(sanitized.encode("utf-8", errors="ignore")).hexdigest()[:12]
        return f"DYNAMIC_ERR_{h}", "build_error"

    def check_memory(self, error_log: str) -> Optional[Dict[str, Any]]:
        """
        Fast-path memory lookup.
        Returns cached solution if found, or None if novel error.
        """
        sig, cat = self.extract_signature(error_log)
        sol = db.lookup_error_solution(sig)
        if sol:
            db.increment_error_usage(sig)
            return {
                "cache_hit": True,
                "error_signature": sig,
                "error_category": sol["error_category"],
                "diagnosis": sol["fix_description"],
                "fix_description": f"[Memory Cache Hit] {sol['fix_description']}",
                "patch_instructions": sol["patch_instructions"],
                "times_reused": sol["times_reused"] + 1,
                "model_source": f"Memory Cache ({sol['model_source']})"
            }
        return None

    def remember_solution(
        self,
        error_log: str,
        diagnosis: str,
        fix_description: str,
        repaired_dockerfile: str,
        model_source: str = "AI Cascade"
    ):
        """Persists a novel verified fix into the Error Resolution Registry."""
        sig, cat = self.extract_signature(error_log)
        db.save_error_solution(
            error_signature=sig,
            error_category=cat,
            sample_error_text=error_log[:600],
            fix_description=diagnosis or fix_description,
            patch_instructions=repaired_dockerfile,
            patch_type="dockerfile_patch",
            model_source=model_source
        )

# Global singleton
error_reg = ErrorRegistry()
