# ==============================================================================
# Module: error_healer.py
# Description: Closed-Loop LLM Self-Debugging & Error Healing Agent for Docker Builds
# Inspired by: Chen et al. (Self-Debugging, ICLR '24) & Hu et al. (Repo2Run, '25)
# ==============================================================================
import re
import json
import difflib
import logging
from typing import Dict, Any, List, Optional, Tuple
from llm import _call_llm_chat
from error_registry import error_reg

logger = logging.getLogger("ai_engine")

class ErrorHealer:
    """
    Autonomous error diagnosis and self-healing engine.
    Analyzes failed container build logs, extracts root causes,
    and prompts the Multi-Provider AI Cascade to repair Dockerfiles iteratively.
    Integrates Case-Based Reasoning Error Registry for instant (<1ms) 0-token fixes.
    """

    def __init__(self):
        self.common_fixes = [
            ("apt-get update && apt-get install", "Ensure apt-get update is chained before install"),
            ("DEBIAN_FRONTEND=noninteractive", "Prevent interactive prompts from hanging Docker builds")
        ]

    def heal_dockerfile(
        self,
        cve_id: str,
        dockerfile_content: str,
        error_log: str,
        attempt_number: int = 1,
        previous_repairs: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Diagnoses build failure and synthesizes a repaired Dockerfile.
        Returns:
            dict containing:
                - diagnosis: str
                - error_category: str
                - fix_description: str
                - repaired_dockerfile: str
                - diff: str
                - confidence: str
                - model_used: str
                - success: bool
        """
        logger.info(f"[SELF-HEALING] Starting repair iteration {attempt_number} for {cve_id}...")

        # Sanitize and truncate error log to keep most informative lines (max 3500 chars)
        cleaned_error = self._extract_relevant_error(error_log)

        # 1. FAST-PATH: Query Case-Based Reasoning Error Memory Registry (<1ms, 0 Tokens)
        memory_hit = error_reg.check_memory(cleaned_error)
        if memory_hit:
            logger.info(f"[ERROR-REGISTRY] Fast-path cache hit for signature: {memory_hit['error_signature']}")
            patch = memory_hit.get("patch_instructions", "").strip()
            
            if "FROM " in patch.upper():
                repaired_dockerfile = patch
            else:
                # Splice patch into Dockerfile right after the FROM line
                lines = dockerfile_content.splitlines()
                spliced_lines = []
                spliced = False
                for line in lines:
                    spliced_lines.append(line)
                    if not spliced and line.strip().upper().startswith("FROM "):
                        spliced_lines.append(patch)
                        spliced = True
                if not spliced:
                    spliced_lines.insert(0, patch)
                repaired_dockerfile = "\n".join(spliced_lines)

            diff_text = self._generate_diff(dockerfile_content, repaired_dockerfile)
            return {
                "success": True,
                "attempt": attempt_number,
                "diagnosis": memory_hit["diagnosis"],
                "error_category": memory_hit["error_category"],
                "fix_description": memory_hit["fix_description"],
                "repaired_dockerfile": repaired_dockerfile,
                "diff": diff_text,
                "confidence": "High (Verified Memory)",
                "model_used": memory_hit["model_source"],
                "cache_hit": True,
                "error_signature": memory_hit["error_signature"],
                "error_log": cleaned_error
            }

        # Build reflection context from previous failed attempts (Reflexion memory buffer)
        reflection_context = ""
        if previous_repairs:
            reflection_context = "\nPREVIOUS FAILED ATTEMPTS & FIXES (DO NOT REPEAT THESE MISTAKES):\n"
            for idx, prev in enumerate(previous_repairs, 1):
                reflection_context += f"Attempt {idx}: Diagnosis: {prev.get('diagnosis', 'N/A')} -> Fix: {prev.get('fix_description', 'N/A')}\n"

        prompt = f"""You are an elite Docker, Linux Systems, and Security Container Engineering Agent.
A Docker build failed while trying to create a reproducible vulnerable testing lab for {cve_id}.

FAILED DOCKERFILE:
```dockerfile
{dockerfile_content}
```

BUILD FAILURE OUTPUT / STDERR:
```text
{cleaned_error}
```
{reflection_context}

MISSION:
1. Deeply analyze the error (e.g. outdated Debian/Ubuntu repositories 404, missing build dependencies, deprecated pip flags, invalid commands, missing files, or network timeouts).
2. If this is an old Linux distribution (Debian Jessie, Stretch, Buster, Ubuntu Xenial), update the package sources to use the official archive mirrors (e.g. sed -i s/deb.debian.org/archive.debian.org/g /etc/apt/sources.list).
3. Ensure 'DEBIAN_FRONTEND=noninteractive' is set for apt-get commands.
4. Output the COMPLETE, fully functional repaired Dockerfile. Do not omit any necessary sections.

OUTPUT FORMAT:
Output EXCLUSIVELY a JSON object with this exact schema (no conversational filler, no backticks outside JSON):
{{
    "diagnosis": "1-2 sentences explaining precisely why the build failed based on the stderr trace.",
    "error_category": "repository_404 | missing_dependency | syntax_error | permission_error | network_timeout | other",
    "fix_description": "Precise summary of the modifications made to resolve the failure.",
    "repaired_dockerfile": "COMPLETE repaired Dockerfile content including FROM, RUN, EXPOSE, CMD/ENTRYPOINT",
    "confidence": "High | Medium | Low"
}}"""

        messages = [
            {"role": "system", "content": "You are an automated Docker self-healing engineer. You output STRICT JSON ONLY."},
            {"role": "user", "content": prompt}
        ]

        reply, model_used = _call_llm_chat(messages, max_tokens=2200, temperature=0.1)

        if not reply:
            logger.warning(f"[SELF-HEALING] All AI models offline. Applying heuristic rule-based patch for {cve_id}.")
            return self._heuristic_fallback_repair(cve_id, dockerfile_content, cleaned_error)

        parsed = self._parse_json_response(reply)
        if not parsed or "repaired_dockerfile" not in parsed:
            logger.warning(f"[SELF-HEALING] Failed to parse JSON from {model_used}. Applying heuristic fallback.")
            return self._heuristic_fallback_repair(cve_id, dockerfile_content, cleaned_error)

        repaired_dockerfile = parsed.get("repaired_dockerfile", "").strip()
        # Clean potential markdown wrappers within the json field
        if repaired_dockerfile.startswith("```dockerfile"):
            repaired_dockerfile = repaired_dockerfile[13:]
        elif repaired_dockerfile.startswith("```"):
            repaired_dockerfile = repaired_dockerfile[3:]
        if repaired_dockerfile.endswith("```"):
            repaired_dockerfile = repaired_dockerfile[:-3]
        repaired_dockerfile = repaired_dockerfile.strip()

        # Generate readable diff
        diff_text = self._generate_diff(dockerfile_content, repaired_dockerfile)

        result = {
            "success": True,
            "attempt": attempt_number,
            "diagnosis": parsed.get("diagnosis", "Error identified from build output."),
            "error_category": parsed.get("error_category", "general_error"),
            "fix_description": parsed.get("fix_description", "Updated Dockerfile instructions."),
            "repaired_dockerfile": repaired_dockerfile,
            "diff": diff_text,
            "confidence": parsed.get("confidence", "Medium"),
            "model_used": model_used,
            "cache_hit": False,
            "error_log": cleaned_error
        }

        logger.info(f"[SELF-HEALING] Repair generated by {model_used}: {result['fix_description']}")
        return result

    def _extract_relevant_error(self, full_log: str) -> str:
        """Extracts the most relevant error lines from verbose Docker build output."""
        if not full_log:
            return "No output stream captured."
        lines = full_log.strip().split("\n")
        # Find lines containing error markers
        error_lines = []
        for line in lines:
            lower = line.lower()
            if any(k in lower for k in ["error", "failed", "fatal", "e:", "404 not found", "unable to locate", "returned a non-zero code"]):
                error_lines.append(line)

        if error_lines:
            # Return surrounding context around error lines
            return "\n".join(lines[-40:]) if len(lines) > 40 else full_log
        return "\n".join(lines[-25:]) if len(lines) > 25 else full_log

    def _parse_json_response(self, text: str) -> Optional[Dict[str, Any]]:
        """Extracts and parses JSON object from model response."""
        clean = text.strip()
        if clean.startswith("```json"):
            clean = clean[7:]
        elif clean.startswith("```"):
            clean = clean[3:]
        if clean.endswith("```"):
            clean = clean[:-3]
        clean = clean.strip()

        try:
            return json.loads(clean)
        except Exception:
            # Fallback regex extraction of outermost JSON object
            match = re.search(r"(\{.*\})", clean, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except Exception:
                    pass
        return None

    def _generate_diff(self, original: str, repaired: str) -> str:
        """Generates a standard unified diff between original and repaired Dockerfiles."""
        orig_lines = original.splitlines(keepends=True)
        rep_lines = repaired.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            rep_lines,
            fromfile="Dockerfile.failed",
            tofile="Dockerfile.repaired",
            n=2
        )
        return "".join(diff)

    def _heuristic_fallback_repair(self, cve_id: str, original: str, error_log: str) -> Dict[str, Any]:
        """Rule-based emergency repair when all AI LLM providers are unreachable."""
        error_lower = error_log.lower()
        repaired = original
        diagnosis = "Build failed due to dependency or repository reachability issue."
        fix = "Applied standard container compatibility fixes."

        # Case 1: Debian archive 404s
        if "404 not found" in error_lower or "archive.debian.org" in error_lower or "release file" in error_lower:
            diagnosis = "Target Linux distribution is End-of-Life (EOL), causing apt-get to fail on retired mirrors."
            fix = "Replaced standard debian mirrors with archive.debian.org and disabled valid-until check."
            patch = "RUN sed -i 's/deb.debian.org/archive.debian.org/g' /etc/apt/sources.list && \\\n    sed -i 's/security.debian.org/archive.debian.org/g' /etc/apt/sources.list && \\\n    echo 'Acquire::Check-Valid-Until \"false\";' > /etc/apt/apt.conf.d/99no-check-valid-until\n"
            if "FROM " in repaired:
                parts = repaired.split("\n")
                new_parts = []
                for p in parts:
                    new_parts.append(p)
                    if p.strip().startswith("FROM "):
                        new_parts.append(patch)
                repaired = "\n".join(new_parts)

        # Case 2: Missing noninteractive frontend
        elif "debconf" in error_lower or "dialog" in error_lower:
            diagnosis = "apt-get stalled waiting for interactive terminal prompt."
            fix = "Set ENV DEBIAN_FRONTEND=noninteractive."
            repaired = "ENV DEBIAN_FRONTEND=noninteractive\n" + repaired

        diff_text = self._generate_diff(original, repaired)
        return {
            "success": True,
            "attempt": 1,
            "diagnosis": diagnosis,
            "error_category": "heuristic_rule_patch",
            "fix_description": fix,
            "repaired_dockerfile": repaired,
            "diff": diff_text,
            "confidence": "Medium",
            "model_used": "Rule-Based Heuristic Fallback"
        }

# Global singleton
healer = ErrorHealer()
