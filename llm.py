# ==============================================================================
# Author: Keysight Team (Integrated for AI Vulnerability Intelligence Platform)
# Description: Multi-Provider Free LLM Cascade with Dynamic Cooldown & Telemetry
# Providers: GroqCloud, Cerebras, OpenRouter Free, Google Gemini, Mistral, Local Ollama
# ==============================================================================
import os
import time
import logging
import random
import re
import json
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

# Set root directory to current project directory
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(ROOT_DIR, "logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

logger = logging.getLogger('ai_engine')
logger.setLevel(logging.INFO)
if not logger.handlers:
    fh = logging.FileHandler(os.path.join(LOGS_DIR, 'cve_analyzer.log'), encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s'))
    logger.addHandler(fh)

api_logger = logging.getLogger('api_call_logger')
api_logger.setLevel(logging.INFO)
if not api_logger.handlers:
    ap_fh = logging.FileHandler(os.path.join(LOGS_DIR, 'apicall.log'), encoding='utf-8')
    ap_fh.setFormatter(logging.Formatter('%(asctime)s - [API] - %(message)s'))
    api_logger.addHandler(ap_fh)

# --- DYNAMIC GETTERS FOR ALL FREE PROVIDERS ---
def _parse_keys(env_var: str) -> list:
    load_dotenv(override=True)
    raw = os.getenv(env_var, "").strip()
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        raw = raw[1:-1].strip()
    return [k.strip().strip('"').strip("'") for k in raw.split(",") if k.strip().strip('"').strip("'")]

def get_groq_keys():
    return _parse_keys("GROQ_API_KEYS") or _parse_keys("GROQ_API_KEY")

def get_cerebras_keys():
    return _parse_keys("CEREBRAS_API_KEYS") or _parse_keys("CEREBRAS_API_KEY")

def get_openrouter_keys():
    return _parse_keys("OPENROUTER_API_KEYS") or _parse_keys("OPENROUTER_API_KEY")

def get_gemini_keys():
    return _parse_keys("GEMINI_API_KEYS") or _parse_keys("GEMINI_API_KEY")

def get_mistral_keys():
    return _parse_keys("MISTRAL_API_KEYS") or _parse_keys("MISTRAL_API_KEY")

def get_ollama_url():
    return os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1").strip()

# --- MODEL POOLS ---
GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "openai/gpt-oss-20b",
    "openai/gpt-oss-120b",
    "qwen/qwen3.8-27b",
    "groq/compound-mini"
]

CEREBRAS_MODELS = [
    "gpt-oss-120b",
    "qwen-3.8-27b",
    "llama-3.3-70b",
    "llama3.1-8b"
]

OPENROUTER_MODELS = [
    "google/gemini-2.0-flash-exp:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "nvidia/nemotron-3.5-lightning:free",
    "liquid/lfm-2.5-2.6b:free",
    "cohere/north-mini-code:free"
]

GEMINI_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-2.5-pro",
    "gemini-flash-latest"
]

MISTRAL_MODELS = [
    "mistral-small-latest",
    "codestral-latest",
    "open-mistral-7b"
]

KEYWORD_LIST = [
    "Ransomware",
    "Lateral Movement",
    "Zero-Click",
    "Default Credentials",
    "Privilege Escalation",
    "Unauthenticated RCE",
    "Data Exfiltration",
    "Remote Code Execution",
    "Denial of Service",
    "Information Disclosure",
    "Authentication Bypass"
]

# --- DYNAMIC KEY COOLDOWN SCHEDULER & TELEMETRY ---
_key_cooldowns = {}

def _is_cooling_down(key: str) -> bool:
    reactivate_at = _key_cooldowns.get(key, 0)
    return time.time() < reactivate_at

def _set_cooldown(key: str, seconds: float = 60.0):
    _key_cooldowns[key] = time.time() + seconds

def _get_cooldown_remaining(key: str) -> float:
    return max(0.0, _key_cooldowns.get(key, 0) - time.time())

# Telemetry registry for System Gateway UI
_telemetry = {
    "groq": {"requests": 0, "success": 0, "failures": 0, "latencies": [], "last_model": None},
    "cerebras": {"requests": 0, "success": 0, "failures": 0, "latencies": [], "last_model": None},
    "openrouter": {"requests": 0, "success": 0, "failures": 0, "latencies": [], "last_model": None},
    "gemini": {"requests": 0, "success": 0, "failures": 0, "latencies": [], "last_model": None},
    "mistral": {"requests": 0, "success": 0, "failures": 0, "latencies": [], "last_model": None},
    "ollama": {"requests": 0, "success": 0, "failures": 0, "latencies": [], "last_model": None}
}

def _mask_key(key: str) -> str:
    if not key:
        return "None"
    return f"...{key[-6:]}" if len(key) > 6 else "******"

def _record_telemetry(provider: str, success: bool, latency: float, model: str):
    if provider in _telemetry:
        t = _telemetry[provider]
        t["requests"] += 1
        if success:
            t["success"] += 1
            t["latencies"].append(round(latency, 2))
            if len(t["latencies"]) > 20:
                t["latencies"].pop(0)
            t["last_model"] = model
        else:
            t["failures"] += 1


def _call_llm_chat(messages, max_tokens=1000, temperature=0.1, custom_models=None):
    """
    Multi-Provider Free LLM Execution Engine:
    Cascades across available zero-cost providers in order:
    1. GroqCloud (Ultra-fast LPU inference)
    2. Google Gemini AI Studio (gemini-2.5-flash, gemini-2.0-flash)
    3. Mistral AI (mistral-small, codestral)
    4. OpenRouter Free Pool (nemotron, gemini-2.0-flash, llama-3.3)
    5. Cerebras Cloud (High-speed free tier)
    6. Local Ollama (100% offline fallback)
    """
    providers_order = [
        ("groq", get_groq_keys(), "https://api.groq.com/openai/v1", GROQ_MODELS, 12.0),
        ("gemini", get_gemini_keys(), "https://generativelanguage.googleapis.com/v1beta/openai/", GEMINI_MODELS, 15.0),
        ("mistral", get_mistral_keys(), "https://api.mistral.ai/v1", MISTRAL_MODELS, 12.0),
        ("openrouter", get_openrouter_keys(), "https://openrouter.ai/api/v1", OPENROUTER_MODELS, 12.0),
        ("cerebras", get_cerebras_keys(), "https://api.cerebras.ai/v1", CEREBRAS_MODELS, 10.0)
    ]

    for p_name, keys, base_url, default_models, timeout_sec in providers_order:
        if not keys:
            continue

        models_to_try = [
            m for m in (custom_models if custom_models else default_models)
            if not (p_name != "gemini" and p_name != "openrouter" and m.startswith("gemini-"))
        ]
        
        for key in keys:
            if _is_cooling_down(key):
                rem = round(_get_cooldown_remaining(key), 1)
                api_logger.info(f"[{p_name.upper()}] Key {_mask_key(key)} cooling down ({rem}s remaining) -> Skipping")
                continue

            for model in models_to_try:
                masked = _mask_key(key)
                req_tag = f"[{p_name.upper()}] [Model: '{model}'] [Key: {masked}]"
                api_logger.info(f"{req_tag} -> Sending completion request...")
                t_start = time.time()

                try:
                    client = OpenAI(base_url=base_url, api_key=key, timeout=timeout_sec)
                    response = client.chat.completions.create(
                        model=model,
                        messages=messages,
                        max_tokens=max_tokens,
                        temperature=temperature
                    )
                    latency = time.time() - t_start
                    raw_content = response.choices[0].message.content if response.choices and response.choices[0].message else ""
                    reply = (raw_content or "").strip()

                    if reply:
                        _record_telemetry(p_name, True, latency, model)
                        success_msg = f"{req_tag} -> SUCCESS in {latency:.2f}s! ({len(reply)} chars)"
                        api_logger.info(success_msg)
                        logger.info(success_msg)
                        return reply, f"{p_name.capitalize()} ({model})"

                except Exception as e:
                    latency = time.time() - t_start
                    _record_telemetry(p_name, False, latency, model)
                    err_str = str(e)
                    err_lower = err_str.lower()

                    # Dynamic key cooldown on rate limit (429) or quota exhaustion
                    if "429" in err_str or "rate limit" in err_lower or "free-models-per-day" in err_lower:
                        cooldown_time = 86400.0 if "free-models-per-day" in err_lower else 60.0
                        _set_cooldown(key, cooldown_time)
                        logger.warning(f"{req_tag} -> Rate limit triggered. Key in cooldown for {cooldown_time}s.")
                        break  # Skip remaining models for this rate-limited key

                    # Payment required / billing quota depleted (e.g. Cerebras 402)
                    elif "402" in err_str or "payment required" in err_lower or "billing" in err_lower:
                        _set_cooldown(key, 86400.0)
                        logger.warning(f"{req_tag} -> Quota depleted / Payment required. Key cooldown for 24h.")
                        break  # Skip remaining models for this key

                    # Invalid API key (401)
                    elif "401" in err_str or "invalid api key" in err_lower:
                        _set_cooldown(key, 86400.0)
                        logger.warning(f"{req_tag} -> Invalid credentials. Key cooldown for 24h.")
                        break

                    err_snippet = err_str[:160].replace("\n", " ")
                    fail_msg = f"{req_tag} -> FAILED in {latency:.2f}s: {err_snippet}"
                    api_logger.warning(fail_msg)
                    logger.warning(fail_msg)
                    time.sleep(0.2)
                    continue

    # Provider 6: Local Ollama (Offline Fallback)
    ollama_url = get_ollama_url()
    try:
        t_start = time.time()
        client = OpenAI(base_url=ollama_url, api_key="ollama", timeout=8.0)
        response = client.chat.completions.create(
            model="llama3.2",
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature
        )
        latency = time.time() - t_start
        raw_content = response.choices[0].message.content if response.choices and response.choices[0].message else ""
        reply = (raw_content or "").strip()
        if reply:
            _record_telemetry("ollama", True, latency, "llama3.2")
            return reply, "Local Ollama (llama3.2)"
    except Exception:
        pass

    logger.error("CRITICAL: All configured LLM providers exhausted after full cascade.")
    api_logger.error("CRITICAL: All configured LLM providers exhausted after full cascade.")
    return None, "Failed (All Models Offline)"


# --- STANDALONE HEURISTIC SIGNATURES ---
KNOWN_EXPLOIT_DOMAINS = [
    "exploit-db.com", "packetstormsecurity.com", "0day.today",
    "rapid7.com/db", "seclists.org/fulldisclosure", "sploitus.com",
    "projectdiscovery/nuclei-templates", "vulhub"
]

KNOWN_ADVISORY_DOMAINS = [
    "msrc.microsoft.com", "cisco.com/security", "ubuntu.com/security",
    "nvd.nist.gov", "cve.mitre.org", "advisories", "bulletin",
    "security.archlinux.org", "access.redhat.com/security", "support.apple.com",
    "apache.org/security", "github.com/advisories"
]

def is_known_exploit_url(url: str) -> bool:
    if not url:
        return False
    u = url.lower()
    return any(d in u for d in KNOWN_EXPLOIT_DOMAINS) or "poc" in u or "exploit" in u

def is_known_advisory_url(url: str) -> bool:
    if not url:
        return False
    u = url.lower()
    return any(d in u for d in KNOWN_ADVISORY_DOMAINS)

def match_exploit_command_signatures(text: str) -> bool:
    if not text:
        return False
    patterns = [
        r"(?:curl|wget)\s+.*?\.(?:sh|py|bin|elf)",
        r"bash\s+-i\s+>&",
        r"nc\s+-[e|c]\s+",
        r"python(?:3)?\s+-[c|m]\s+",
        r"msfconsole|msfvenom",
        r"searchsploit\s+"
    ]
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False


def ai_link_classifier(text_content, url=None, thread_models=None):
    """
    3-Way Threat Intel Classifier with Fast-Path Heuristic Pre-Filtering:
    1. Checks URL against known exploit signatures or runnable shell/command patterns -> 'POC' (<1ms, 0 AI tokens)
    2. Checks URL against known vendor advisory portals (Microsoft, Cisco, Siemens, etc.) -> 'VENDOR_FIX' (<1ms, 0 AI tokens)
    3. Analyzes GitHub code vs commit/PR vs advisory paths (<1ms)
    4. Ambiguous Links Only: Dispatches to Multi-Provider AI Engine
    Returns: 'POC', 'VENDOR_FIX', or 'INFO'
    """
    # Heuristic Rule 1: Exploit link signature or runnable command match
    if (url and is_known_exploit_url(url)) or match_exploit_command_signatures(text_content):
        return "POC"

    # Heuristic Rule 2: Official vendor security bulletin match
    if url and is_known_advisory_url(url):
        return "VENDOR_FIX"

    # Heuristic Rule 3: GitHub smart path inspection
    if url and "github.com" in url.lower():
        u_lower = url.lower()
        if "/commit/" in u_lower or "/pull/" in u_lower or "/security/advisories/" in u_lower:
            return "VENDOR_FIX"
        if any(u_lower.endswith(ext) for ext in [".py", ".c", ".cpp", ".go", ".sh", ".rb", ".pl"]):
            return "POC"
        if "/issues/" in u_lower:
            return "INFO"

    if not text_content or len(text_content.strip()) < 25:
        return "INFO"

    # Fast AI fallback for ambiguous text
    prompt = """You are an expert threat intelligence classifier. Read the text extracted from a security webpage.
Classify this content into EXACTLY one of these three categories:
1. 'POC' - Working Proof of Concept code, exploit payload, or weaponization steps.
2. 'VENDOR_FIX' - Official vendor security advisory, patch notification, or mitigation guide.
3. 'INFO' - General CVE discussion, news blog, or bug tracker without runnable exploit.
Output EXACTLY and ONLY one word: 'POC', 'VENDOR_FIX', or 'INFO'."""

    truncated_text = text_content[:4000]
    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": f"Text:\n{truncated_text}"}
    ]

    reply, model_used = _call_llm_chat(messages, max_tokens=10, temperature=0.0, custom_models=thread_models)
    if reply:
        clean = reply.strip().upper()
        if "POC" in clean:
            return "POC"
        elif "VENDOR" in clean or "FIX" in clean or "PATCH" in clean:
            return "VENDOR_FIX"
        else:
            return "INFO"
    return "INFO"


def ai_poc_detector(text_content, url=None, thread_models=None):
    """Backwards-compatible wrapper: returns True if classified as POC."""
    return ai_link_classifier(text_content, url=url, thread_models=thread_models) == "POC"


def analyze_individual_cve(cve_id, combined_text_data, thread_models=None):
    """
    Extracts structured intelligence with strict XML schema for a single CVE.
    Returns: summary, action, poc, vendor, product, keywords, model_used
    """
    logger.info(f"AI Analyzing {cve_id} via Multi-Provider Cascade...")

    strict_prompt = f"""You are a precise cybersecurity analyst. You MUST output your response EXACTLY using the following XML tags. Do NOT add any conversational text outside these tags.

<summary>Provide a 5 to 6 line summary of the threat, including root cause and potential impact.</summary>
<action>Provide a 1 to 2 line recommended mitigation or immediate defense action.</action>
<poc>Identify any known exploitation method, recreation prerequisites, or state 'None documented'.</poc>
<vendor>Vendor Name or 'Unknown'</vendor>
<product>Product Name or 'Unknown'</product>
<keywords>Comma-separated keywords from this exact list: {', '.join(KEYWORD_LIST)}</keywords>"""

    messages = [
        {"role": "system", "content": strict_prompt},
        {"role": "user", "content": f"Data for {cve_id}:\n{combined_text_data}"}
    ]

    raw_text, model_used = _call_llm_chat(messages, max_tokens=1500, temperature=0.1, custom_models=thread_models)

    if not raw_text:
        return "API Offline or Rate Limited.", "Review vendor bulletin and patch immediately.", "None", "Unknown", "Unknown", "None", "Failed (All Models Offline)"

    def extract_tag(text, tag):
        match = re.search(rf'<{tag}>(.*?)</{tag}>', text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        known_tags = "summary|action|poc|vendor|product|keywords"
        match_fallback = re.search(rf'<{tag}>(.*?)(?=<(?:{known_tags})\b|$)', text, flags=re.IGNORECASE | re.DOTALL)
        if match_fallback:
            val = match_fallback.group(1).strip()
            val = re.sub(r'</\w+>', '', val).strip()
            if val:
                return val
        return None

    s = extract_tag(raw_text, 'summary')
    a = extract_tag(raw_text, 'action')
    p = extract_tag(raw_text, 'poc')
    v = extract_tag(raw_text, 'vendor')
    pr = extract_tag(raw_text, 'product')
    kw = extract_tag(raw_text, 'keywords')

    if p:
        p = p.replace('```html', '').replace('```python', '').replace('```', '').strip()

    if s and a and p and v and pr and kw:
        logger.info(f"[SUCCESS] Successfully analyzed {cve_id} using: {model_used}")
        return s, a, p, v, pr, kw, model_used

    # Robust fallback for partial tags
    fallback_summary = s
    if not fallback_summary:
        cleaned_text = re.sub(r'<[^>]+>', ' ', raw_text)
        fallback_summary = ' '.join(cleaned_text.split())[:350]
        if not fallback_summary:
            fallback_summary = "Analysis details extracted from threat feeds."

    return (
        fallback_summary,
        (a or "Review manually and apply vendor patches."),
        (p or "None"),
        (v or "Unknown"),
        (pr or "Unknown"),
        (kw or "None"),
        model_used
    )


def generate_lab_environment(cve_data, thread_models=None):
    """
    Generates a secure Docker/VM validation lab environment plan using the Multi-Provider Cascade.
    Returns: dictionary with docker blueprint, vm recommendation, ports, credentials, etc.
    """
    cve_id = cve_data.get("cve_id", "Unknown CVE")
    vendor = cve_data.get("vendor", "Unknown Vendor")
    product = cve_data.get("product", "Unknown Product")
    description = cve_data.get("description", "")

    prompt = f"""You are a Vulnerability Research & Defense Engineer. Generate a secure Docker/VM validation lab environment plan for {cve_id} affecting {vendor} {product}.
Description: {description}

Provide the output EXCLUSIVELY in the following JSON schema format without markdown backticks or extra commentary:
{{
    "docker_recommendation": "# Dockerfile configuration blueprint\\nFROM ...\\nRUN ...\\nEXPOSE ...",
    "vm_recommendation": "VM OS and configuration suggestions",
    "dependencies": ["package-name-1", "package-name-2"],
    "ports": [80, 443],
    "credentials": "Default or custom setup accounts",
    "installation_steps": ["step 1: ...", "step 2: ..."],
    "verification_steps": ["validation check 1", "validation check 2"],
    "lab_difficulty": "Low"
}}"""

    messages = [
        {"role": "system", "content": "You are a secure lab environment architect. You output ONLY valid JSON."},
        {"role": "user", "content": prompt}
    ]

    raw_content, model_used = _call_llm_chat(messages, max_tokens=1500, temperature=0.1, custom_models=thread_models)
    
    if not raw_content:
        return {"error": f"Failed to generate lab setup: All AI models offline or rate-limited. (Last attempt: {model_used})"}

    clean = raw_content.strip()
    if clean.startswith("```json"):
        clean = clean[7:]
    elif clean.startswith("```"):
        clean = clean[3:]
    if clean.endswith("```"):
        clean = clean[:-3]
    clean = clean.strip()

    try:
        data = json.loads(clean)
        data["generated_by"] = model_used
        return data
    except Exception as e:
        match = re.search(r'(\{.*\})', clean, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(1))
                data["generated_by"] = model_used
                return data
            except Exception:
                pass
        return {
            "error": f"Model returned non-JSON format: {str(e)}",
            "raw_output": clean[:300],
            "generated_by": model_used
        }


def generate_priority_summary(cve_summaries_list):
    """Generates an executive CISO briefing across a batch of analyzed CVEs."""
    if not cve_summaries_list:
        return "No vulnerabilities were identified."

    messages = [
        {"role": "system", "content": "You are a Chief Information Security Officer (CISO). Write a concise, 1-paragraph executive summary highlighting the most dangerous threats in the provided list."},
        {"role": "user", "content": f"Vulnerabilities:\n{chr(10).join(cve_summaries_list)}"}
    ]

    summary, model_used = _call_llm_chat(messages, max_tokens=600, temperature=0.2)
    return summary or "Executive summary could not be generated due to upstream model availability."


def get_llm_status():
    """Returns telemetry of available AI providers, keys, response times, and model lists."""
    groq_keys = get_groq_keys()
    cerebras_keys = get_cerebras_keys()
    openrouter_keys = get_openrouter_keys()
    gemini_keys = get_gemini_keys()
    mistral_keys = get_mistral_keys()

    def _avg_latency(p_name):
        l = _telemetry.get(p_name, {}).get("latencies", [])
        return round(sum(l) / len(l), 2) if l else None

    return {
        "providers": {
            "groq": {
                "name": "GroqCloud (LPU)",
                "configured": bool(groq_keys),
                "keys_count": len(groq_keys),
                "models": GROQ_MODELS,
                "avg_latency_sec": _avg_latency("groq"),
                "success_count": _telemetry["groq"]["success"],
                "failures_count": _telemetry["groq"]["failures"],
                "cooling_down": any(_is_cooling_down(k) for k in groq_keys) if groq_keys else False
            },
            "gemini": {
                "name": "Google Gemini",
                "configured": bool(gemini_keys),
                "keys_count": len(gemini_keys),
                "models": GEMINI_MODELS,
                "avg_latency_sec": _avg_latency("gemini"),
                "success_count": _telemetry["gemini"]["success"],
                "failures_count": _telemetry["gemini"]["failures"],
                "cooling_down": any(_is_cooling_down(k) for k in gemini_keys) if gemini_keys else False
            },
            "mistral": {
                "name": "Mistral AI",
                "configured": bool(mistral_keys),
                "keys_count": len(mistral_keys),
                "models": MISTRAL_MODELS,
                "avg_latency_sec": _avg_latency("mistral"),
                "success_count": _telemetry["mistral"]["success"],
                "failures_count": _telemetry["mistral"]["failures"],
                "cooling_down": any(_is_cooling_down(k) for k in mistral_keys) if mistral_keys else False
            },
            "openrouter": {
                "name": "OpenRouter Free",
                "configured": bool(openrouter_keys),
                "keys_count": len(openrouter_keys),
                "models": OPENROUTER_MODELS,
                "avg_latency_sec": _avg_latency("openrouter"),
                "success_count": _telemetry["openrouter"]["success"],
                "failures_count": _telemetry["openrouter"]["failures"],
                "cooling_down": any(_is_cooling_down(k) for k in openrouter_keys) if openrouter_keys else False
            },
            "cerebras": {
                "name": "Cerebras Cloud",
                "configured": bool(cerebras_keys),
                "keys_count": len(cerebras_keys),
                "models": CEREBRAS_MODELS,
                "avg_latency_sec": _avg_latency("cerebras"),
                "success_count": _telemetry["cerebras"]["success"],
                "failures_count": _telemetry["cerebras"]["failures"],
                "cooling_down": any(_is_cooling_down(k) for k in cerebras_keys) if cerebras_keys else False
            }
        },
        "total_active_keys": len(groq_keys) + len(cerebras_keys) + len(openrouter_keys) + len(gemini_keys) + len(mistral_keys)
    }