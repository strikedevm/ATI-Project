import os
import base64
import random
import streamlit as st

from cve_collector import CVECollector
from github_finder import GitHubFinder
from exploit_finder import ExploitFinder
from advisory_finder import AdvisoryFinder
from ai_generator import AIGenerator
from styles import apply_custom_css
from utils import format_json_output
from database import db
from docker_manager import docker_mgr
from lab_verifier import verifier
from error_healer import healer
from error_registry import error_reg
from ssh_sandbox import ssh_sandbox
from os_archives import os_archives

st.set_page_config(
    page_title="Vulnerability Lab Builder",
    layout="wide",
    initial_sidebar_state="collapsed"
)
apply_custom_css()

collector = CVECollector()
github_finder = GitHubFinder()
exploit_finder = ExploitFinder()
advisory_finder = AdvisoryFinder()
ai_engine = AIGenerator()

# --- Helper: Base64 Logo Encoding ---
def get_base64_image(image_path: str) -> str:
    try:
        full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), image_path)
        with open(full_path, "rb") as img_file:
            return base64.b64encode(img_file.read()).decode()
    except Exception:
        return ""

battle_logo_b64 = get_base64_image("assets/cyber_battle_logo.jpg")

# --- Header Hero Banner with Attack / Battle Symbol ---
if battle_logo_b64:
    st.markdown(f"""
        <div class="header-hero">
            <img class="header-hero-img" src="data:image/jpeg;base64,{battle_logo_b64}" alt="Cyber Warfare Attack Shield" />
            <div>
                <div class="hero-title">Vulnerability Lab Builder</div>
                <div class="hero-subtitle">Automated CVE Multi-Source Threat Intelligence & Isolated Sandbox Replication Engine</div>
            </div>
        </div>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
        <div class="header-hero">
            <div class="hero-title">⚔️ Vulnerability Lab Builder</div>
            <div class="hero-subtitle">Automated CVE Multi-Source Threat Intelligence & Isolated Sandbox Replication Engine</div>
        </div>
    """, unsafe_allow_html=True)

# --- Active CVE State Initialization ---
if "active_cve" not in st.session_state:
    st.session_state.active_cve = ""

# --- Search Form with Search and Live Re-fetch Side by Side ---
with st.form("cve_search_form", clear_on_submit=False):
    col_input, col_search, col_refetch = st.columns([5.2, 1.3, 1.3])
    with col_input:
        cve_query = st.text_input(
            "CVE Input",
            value=st.session_state.active_cve,
            placeholder="Enter CVE ID (e.g., CVE-2016-3088, CVE-2021-44228, CVE-2024-3400) or click Search for random CVE...",
            label_visibility="collapsed"
        ).strip().upper()
    with col_search:
        search_clicked = st.form_submit_button("🔍 Search CVE", type="primary", use_container_width=True)
    with col_refetch:
        refetch_clicked = st.form_submit_button("🔄 Live Re-fetch", use_container_width=True)

# Handle Live Re-fetch
if refetch_clicked:
    target_cve = cve_query or st.session_state.active_cve
    if target_cve:
        st.session_state.active_cve = target_cve
        st.session_state[f"force_refresh_{target_cve}"] = True
        st.rerun()

# Handle Search:
# 1. If user typed a CVE -> load that CVE
# 2. If user clicked with empty text -> pick a random CVE run before
if search_clicked:
    if cve_query:
        st.session_state.active_cve = cve_query
    else:
        past_cves = db.get_recent_searches(50)
        if not past_cves:
            all_records = db.get_all_cves(50)
            past_cves = [r["cve_id"] for r in all_records]
        if not past_cves:
            past_cves = ["CVE-2016-3088", "CVE-2021-44228", "CVE-2024-3400", "CVE-2023-46604"]
        
        options = [c for c in past_cves if c != st.session_state.active_cve]
        chosen_cve = random.choice(options if options else past_cves)
        st.session_state.active_cve = chosen_cve
        st.rerun()

cve_id = st.session_state.active_cve

# ==============================================================================
# CVE INTELLIGENCE VIEW
# ==============================================================================
if cve_id:
    force_refresh_key = f"force_refresh_{cve_id}"
    is_force_refresh = st.session_state.get(force_refresh_key, False)
    
    # 1. Attempt retrieval from SQLite Database
    cached_payload = db.get_cve_data(cve_id) if not is_force_refresh else None
    is_cached = cached_payload is not None

    if is_cached:
        cve_data = cached_payload["cve_data"]
        github_pocs = cached_payload["github_pocs"]
        extra_intel = cached_payload["extra_intel"]
    else:
        with st.spinner(f"Aggregating multi-source threat intelligence for {cve_id}..."):
            cve_data = collector.fetch_cve_data(cve_id)
            if cve_data:
                github_pocs = github_finder.search_pocs(cve_id)
                extra_intel = exploit_finder.fetch_all_intelligence(cve_id, references=cve_data.get("references", []))
                # Persist to SQLite Database
                db.save_cve_data(cve_data, github_pocs, extra_intel)
                if is_force_refresh:
                    st.session_state[force_refresh_key] = False

    if not cve_data:
        st.error(f"CVE identification footprint data for '{cve_id}' could not be loaded from source APIs or local database.")
    else:
        # Filter for important references only
        advisories = advisory_finder.find_advisories(
            cve_id,
            cve_data.get("references", []),
            vendor=cve_data.get("vendor", ""),
            product=cve_data.get("product", "")
        )
        vulhub_matches = [it for it in extra_intel if it.get("is_vulhub")]
        
        # --- Top Metric Cards (Responsive, auto-wrapped, no overlapping) ---
        cols = st.columns(6)
        top_metrics = [
            ("VENDOR", cve_data.get("vendor", "N/A")),
            ("PRODUCT", cve_data.get("product", "N/A")),
            ("PRIMARY SEVERITY", cve_data.get("cvss_severity", "N/A")),
            ("CWE ID", cve_data.get("cwe", "N/A")),
            ("CVSS V3 SCORE", f"{float(cve_data['primary_v3_score']):.1f}" if cve_data.get('primary_v3_score') not in (None, "N/A") else "N/A"),
            ("CISA KEV", "YES" if cve_data.get("is_kev") else "NO")
        ]
        for idx, (title, raw_val) in enumerate(top_metrics):
            with cols[idx]:
                display_val = str(raw_val).replace("_", " ")
                val_len = len(display_val)
                if val_len > 22:
                    val_class = "metric-value metric-value-xs"
                elif val_len > 12:
                    val_class = "metric-value metric-value-sm"
                else:
                    val_class = "metric-value"

                st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-title">{title}</div>
                        <div class="{val_class}">{display_val}</div>
                    </div>
                """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # --- Navigation Tabs ---
        tab_overview, tab_ai_intel, tab_lab, tab_pocs_blogs, tab_refs, tab_downloads, tab_database = st.tabs([
            "📋 Overview", "🧠 AI Threat Intel", "🧪 Lab Builder", "🪲 PoCs / Blogs", "🔗 References", "💾 Downloads", "🗄️ Database"
        ])
        
        # --- TAB 1: OVERVIEW ---
        with tab_overview:
            st.subheader("Description")
            st.write(cve_data.get("description", "No description provided."))
            st.markdown(f"**Published:** {cve_data.get('published', 'N/A')} | **Last Modified:** {cve_data.get('modified', 'N/A')}")
            
            st.markdown("---")
            
            # --- CVSS Scores Section ---
            st.markdown(f"### CVSS scores for {cve_data.get('cve_id', cve_id)}")
            st.markdown("<br>", unsafe_allow_html=True)
            
            v3_scores = cve_data.get("cvss_v3_assessments", [])
            v2_scores = cve_data.get("cvss_v2_assessments", [])
            
            def display_cvss_group(scores_list, header_title):
                st.markdown(f"#### **{header_title}**")
                if not scores_list:
                    st.caption("No scores available for this version.")
                    return
                
                for item in scores_list:
                    raw_score = item.get("score", "N/A")
                    try:
                        formatted_score = f"{float(raw_score):.1f}"
                    except (ValueError, TypeError):
                        formatted_score = str(raw_score)
                    
                    severity = item.get("severity", "").upper()
                    source = item.get("source", "N/A")
                    vector = item.get("vector", "N/A")
                    
                    col1, col2, col3 = st.columns([1.5, 1.5, 4])
                    with col1:
                        st.markdown(f"**{source}**")
                    with col2:
                        st.markdown(f"**Base Score:** `{formatted_score} {severity}`")
                    with col3:
                        st.markdown(f"**Vector:** `{vector}`")
                    st.markdown("<div style='margin-bottom: 8px;'></div>", unsafe_allow_html=True)
                st.markdown("---")

            display_cvss_group(v3_scores, "CVSS v3")
            display_cvss_group(v2_scores, "CVSS v2")

        # --- TAB 2: AI THREAT INTEL ---
        with tab_ai_intel:
            st.subheader("🧠 Multi-Model AI Threat Intelligence & CISO Assessment")
            st.caption("Powered by the Multi-Provider Cascade (Groq / Gemini / Mistral / OpenRouter / Cerebras)")
            
            ai_intel_key = f"ai_intel_{cve_id}"
            if ai_intel_key not in st.session_state:
                cached_ai_db = db.get_ai_analysis(cve_id)
                if cached_ai_db:
                    st.session_state[ai_intel_key] = cached_ai_db

            if st.button("Run AI Deep Threat Analysis", key="btn_run_ai_intel"):
                with st.spinner("Executing multi-provider AI threat analysis..."):
                    combined_input = f"Vendor: {cve_data.get('vendor')}\nProduct: {cve_data.get('product')}\nDescription: {cve_data.get('description')}\nCVSS: {cve_data.get('cvss_severity')}"
                    s, a, p, v, pr, kw, model_used = ai_engine.analyze_cve(cve_id, combined_input)
                    ai_payload = {
                        "summary": s,
                        "action": a,
                        "poc": p,
                        "vendor": v,
                        "product": pr,
                        "keywords": kw,
                        "model_used": model_used
                    }
                    st.session_state[ai_intel_key] = ai_payload
                    db.save_ai_analysis(cve_id, ai_payload)
                    st.rerun()
            
            cached_ai = st.session_state.get(ai_intel_key, None)
            if cached_ai:
                st.markdown(f"""
                    <div class="ai-box">
                        <span style="font-size: 11px; text-transform: uppercase; color: #818CF8; font-weight: bold;">
                            ⚡ Model Engine: {cached_ai.get('model_used', 'AI Cascade')} &bull; Cached in SQLite
                        </span>
                        <h4 style="margin-top: 8px; color: #F8FAFC;">Executive Threat Summary</h4>
                        <p style="color: #CBD5E1; line-height: 1.6;">{cached_ai.get('summary', '')}</p>
                    </div>
                """, unsafe_allow_html=True)
                
                st.markdown("#### 🛡️ Recommended Defense Action")
                st.info(cached_ai.get("action", ""))
                
                st.markdown("#### 🎯 Exploitation & Recreation Footprint")
                poc_content = cached_ai.get("poc", "")
                if poc_content and poc_content.lower() != "none":
                    st.code(poc_content, language="text")
                else:
                    st.caption("No direct runnable exploit payloads reported in primary intelligence feeds.")
                
                st.markdown("#### 🏷️ Threat Classification Keywords")
                if cached_ai.get("keywords"):
                    kw_list = [k.strip() for k in cached_ai["keywords"].split(",") if k.strip()]
                    kw_html = " ".join([f"<span class='badge-tag badge-poc'>{k}</span>" for k in kw_list])
                    st.markdown(kw_html, unsafe_allow_html=True)
            else:
                st.info("Click 'Run AI Deep Threat Analysis' above to generate an executive briefing and technical evaluation.")

        # --- TAB 3: LAB BUILDER (3-TIER PROVISIONING ENGINE) ---
        with tab_lab:
            st.subheader("Multi-Tier Replication Sandbox & Execution Engine")
            st.caption("Tier 1: Docker/Vulhub Containers &bull; Tier 2: Remote Tri-OS SSH Sandboxes &bull; Tier 3: Legacy OS Archival Intelligence")

            # 0. Case-Based Reasoning Error Memory Registry Telemetry
            cached_errors = db.get_all_error_solutions()
            num_cached_solutions = len(cached_errors)
            total_reuses = sum(e.get("times_reused", 0) for e in cached_errors)

            st.markdown(f"""
                <div style="background: rgba(88, 28, 135, 0.25); border: 1px solid rgba(168, 85, 247, 0.4); border-radius: 10px; padding: 12px 18px; margin-bottom: 14px; display: flex; align-items: center; justify-content: space-between;">
                    <div>
                        <span class="badge-tag badge-memory">⚡ CASE-BASED ERROR MEMORY</span>
                        <strong style="color: #F8FAFC; margin-left: 10px;">{num_cached_solutions} Verified Build Solutions Cached</strong>
                        <span style="color: #DDD6FE; font-size: 13px; margin-left: 10px;">({total_reuses} Instant Reuses &bull; 0 Tokens &bull; &lt;1ms Fast-Path)</span>
                    </div>
                    <div style="font-size: 12px; color: #C084FC;">Auto-patches recurring build failures</div>
                </div>
            """, unsafe_allow_html=True)

            with st.expander("🧠 View Case-Based Error Resolution Registry (Live Cache)"):
                if cached_errors:
                    for err_item in cached_errors:
                        st.markdown(f"**`{err_item['error_signature']}`** ({err_item['error_category']}) &bull; Reused: `{err_item['times_reused']}` times &bull; Source: `{err_item['model_source']}`")
                        st.caption(err_item['fix_description'])
                        st.code(err_item['patch_instructions'][:350] + ("..." if len(err_item['patch_instructions']) > 350 else ""), language="dockerfile")
                else:
                    st.info("No error solutions cached yet. When builds fail and heal, solutions are saved here automatically.")

            # 3-Tier Provisioning Tabs
            tier_docker, tier_ssh, tier_iso = st.tabs([
                "🐳 Tier 1: Local Container Sandbox (Docker / Vulhub)",
                "🖥️ Tier 2: Remote SSH Sandboxes (Linux / Windows / macOS)",
                "💿 Tier 3: Legacy OS Archival Intelligence & ISO Finder"
            ])

            # ==================================================================
            # TIER 1: DOCKER / VULHUB ISOLATED CONTAINERS
            # ==================================================================
            with tier_docker:
                # 1. Docker Daemon Status Ribbon
                docker_online, docker_msg = docker_mgr.is_docker_available()
                badge_class = "badge-active" if docker_online else "badge-offline"
                badge_label = "DOCKER ENGINE ONLINE" if docker_online else "DOCKER ENGINE OFFLINE"
                st.markdown(f"""
                    <div class="docker-status-card">
                        <div>
                            <span class="badge-tag {badge_class}">{badge_label}</span>
                            <strong style="color: #F8FAFC; margin-left: 10px;">{docker_msg}</strong>
                        </div>
                        <div style="font-size: 12px; color: #94A3B8;">
                            {'Ready for isolated container deployments' if docker_online else 'Start Docker Desktop on Windows to build & execute live containers'}
                        </div>
                    </div>
                """, unsafe_allow_html=True)

                # Check if container is currently deployed / running
                container_state = docker_mgr.get_container_status(cve_id)
                is_running = container_state.get("is_running", False)
                saved_deploy = container_state.get("saved_record") or db.get_lab_deployment(cve_id)

                # Active Running Container Control Center (if running)
                if is_running:
                    host_port = saved_deploy.get("host_port", 8080) if saved_deploy else 8080
                    st.markdown(f"""
                        <div class="audit-card">
                            <span class="badge-tag badge-active">🟢 LIVE LAB CONTAINER RUNNING</span>
                            <h4 style="margin: 8px 0; color: #F0FDF4;">⚡ Target Sandbox Active on Port {host_port}</h4>
                            <p style="color: #BBF7D0; font-size: 13px;">
                                Container ID: <code>{container_state.get('container_id', 'Active')}</code> &bull; Status: <code>{container_state.get('status_text', 'Up')}</code>
                            </p>
                            <a href="http://localhost:{host_port}" target="_blank" style="color: #4ADE80; font-weight: bold; text-decoration: underline; margin-right: 15px;">🌐 Open Target Application (http://localhost:{host_port})</a>
                        </div>
                    """, unsafe_allow_html=True)

                    col_stop, col_restart, col_audit, col_logs = st.columns(4)
                    with col_stop:
                        if st.button("⏹️ Stop Lab Container", key=f"btn_stop_{cve_id}", use_container_width=True):
                            with st.spinner("Terminating container..."):
                                docker_mgr.stop_lab(cve_id)
                                st.success("Container stopped.")
                                st.rerun()
                    with col_restart:
                        if st.button("🔄 Restart Lab", key=f"btn_restart_{cve_id}", use_container_width=True):
                            with st.spinner("Restarting container..."):
                                docker_mgr.stop_lab(cve_id)
                                st.info("Restarted container.")
                                st.rerun()
                    with col_audit:
                        if st.button("🩺 Run Health Audit", key=f"btn_audit_{cve_id}", use_container_width=True):
                            with st.spinner("Probing container TCP and HTTP services..."):
                                audit_res = verifier.audit_container(cve_id, host="localhost", port=host_port)
                                st.session_state[f"audit_{cve_id}"] = audit_res
                                if saved_deploy:
                                    saved_deploy["audit_details"] = audit_res
                                    saved_deploy["health_status"] = audit_res.get("health_status", "unknown")
                                    db.save_lab_deployment(cve_id, saved_deploy)
                                st.rerun()
                    with col_logs:
                        show_logs = st.button("📜 Toggle Container Logs", key=f"btn_toggle_logs_{cve_id}", use_container_width=True)

                    # Show health audit results if available
                    audit_data = st.session_state.get(f"audit_{cve_id}") or (saved_deploy.get("audit_details") if saved_deploy else None)
                    if audit_data:
                        st.markdown("##### 🩺 Live Service Health & Verification Audit")
                        for chk in audit_data.get("checks", []):
                            icon = "✅" if chk.get("passed") else "❌"
                            st.markdown(f"{icon} **{chk.get('name')}**: `{chk.get('detail')}`")

                    # Container live logs
                    if show_logs or st.session_state.get(f"show_logs_{cve_id}", False):
                        st.session_state[f"show_logs_{cve_id}"] = True
                        st.markdown("##### 📜 Container Real-time Stdout/Stderr")
                        c_logs = docker_mgr.get_container_logs(cve_id, tail=60)
                        st.code(c_logs or "No logs emitted yet.", language="text")

                    st.markdown("---")

                # Vulhub Environment Card (Priority Lab)
                if vulhub_matches:
                    v_top = vulhub_matches[0]
                    st.markdown(f"""
                        <div class="vulhub-card">
                            <span class="badge-tag badge-vulhub">⭐ OFFICIAL VULHUB LAB DISCOVERED</span>
                            <h4 style="margin: 8px 0; color: #F0F9FF;">🐳 Pre-built Docker Environment Available</h4>
                            <p style="color: #BAE6FD; font-size: 13px;">
                                An official Vulhub reproducible container blueprint exists for this CVE.
                            </p>
                            <a href="{v_top['url']}" target="_blank" style="color: #38BDF8; font-weight: bold; text-decoration: underline; margin-right: 15px;">📂 Browse Vulhub Environment</a>
                            <a href="{v_top['docker_compose_url']}" target="_blank" style="color: #7DD3FC; text-decoration: underline;">📄 View Raw docker-compose.yml</a>
                        </div>
                    """, unsafe_allow_html=True)

                    if not is_running:
                        col_v1, col_v2 = st.columns([3, 1])
                        with col_v1:
                            if st.button("🐳 Deploy Verified Vulhub Container Environment", key=f"btn_deploy_vulhub_{cve_id}", use_container_width=True):
                                if not docker_online:
                                    st.warning("⚠️ Docker Desktop is currently offline. Please start Docker Desktop on Windows to deploy live containers.")
                                else:
                                    with st.status(f"Deploying Vulhub environment for {cve_id}...", expanded=True) as status_box:
                                        def update_status(msg):
                                            status_box.write(f"&bull; {msg}")
                                        v_res = docker_mgr.deploy_vulhub_lab(cve_id, v_top['docker_compose_url'], progress_cb=update_status)
                                        if v_res.get("success"):
                                            status_box.update(label="Vulhub Lab Deployed Successfully!", state="complete")
                                            st.success(f"Lab is active at: {v_res.get('url')}")
                                            st.rerun()
                                        else:
                                            status_box.update(label="Vulhub Deployment Failed", state="error")
                                            st.error(v_res.get("error", "Deployment failed."))

                # Blueprint Generation & Deployment with AI Self-Healing
                lab_key = f"lab_{cve_id}"
                if lab_key not in st.session_state:
                    cached_lab_db = db.get_lab_blueprint(cve_id)
                    if cached_lab_db:
                        st.session_state[lab_key] = cached_lab_db

                col_btn1, col_btn2 = st.columns([2, 3])
                with col_btn1:
                    if st.button("Generate Lab Configuration Engine", key="btn_gen_lab", use_container_width=True):
                        with st.spinner("Prompting underlying model cascade..."):
                            lab_res = ai_engine.generate_lab_environment(cve_data)
                            st.session_state[lab_key] = lab_res
                            if "error" not in lab_res:
                                db.save_lab_blueprint(cve_id, lab_res)
                            st.rerun()

                lab_data = st.session_state.get(lab_key, None)
                if lab_data:
                    if "error" in lab_data:
                        st.error(lab_data["error"])
                    else:
                        if lab_data.get("generated_by"):
                            st.caption(f"⚡ Blueprint generated via: **{lab_data.get('generated_by')}** &bull; Cached in SQLite")

                        st.markdown(f"### Lab Complexity: `{lab_data.get('lab_difficulty', 'Medium')}`")
                        dockerfile_text = lab_data.get("docker_recommendation", "# No docker snippet returned")
                        st.code(dockerfile_text, language="dockerfile", line_numbers=True)

                        # Deployment Action Panel with Self-Healing Option
                        if not is_running:
                            st.markdown("#### 🚀 Automated Container Sandbox Provisioning")
                            auto_heal_enabled = st.checkbox(
                                "🩹 Enable Closed-Loop AI Self-Healing Agent (Fast-path memory + multi-turn repair)",
                                value=True,
                                key=f"chk_heal_{cve_id}",
                                help="Queries Error Memory Registry (<1ms) first. If novel error, prompts LLM to analyze stderr and patch Dockerfile."
                            )

                            ports_list = lab_data.get("ports", [80])
                            target_p = int(ports_list[0]) if ports_list and str(ports_list[0]).isdigit() else 80

                            if st.button("🚀 Deploy Blueprint via Docker (Build, Run & Self-Heal)", key=f"btn_deploy_blueprint_{cve_id}", use_container_width=True):
                                if not docker_online:
                                    st.warning("⚠️ Docker Desktop is currently offline. Please start Docker Desktop on Windows to build and run live containers.")
                                else:
                                    with st.status(f"Building isolated container for {cve_id}...", expanded=True) as build_box:
                                        def update_build(msg):
                                            build_box.write(f"&bull; {msg}")

                                        deploy_res = docker_mgr.build_and_deploy_blueprint(
                                            cve_id=cve_id,
                                            dockerfile_content=dockerfile_text,
                                            target_port=target_p,
                                            auto_heal=auto_heal_enabled,
                                            max_retries=3,
                                            progress_cb=update_build
                                        )

                                        if deploy_res.get("success"):
                                            build_box.update(label="Container Built and Running Successfully!", state="complete")
                                            st.success(f"Lab is active at: {deploy_res.get('url')} (Repairs applied: {deploy_res.get('repair_count', 0)})")
                                            st.rerun()
                                        else:
                                            build_box.update(label="Build / Deployment Failed", state="error")
                                            st.error(deploy_res.get("error", "Build failed."))
                                            if deploy_res.get("full_log"):
                                                with st.expander("View Full Build Stderr Log"):
                                                    st.code(deploy_res["full_log"], language="text")

                        # Self-Healing Telemetry & History (if repairs occurred)
                        repairs = saved_deploy.get("repair_history", []) if saved_deploy else []
                        if repairs:
                            st.markdown("---")
                            with st.expander(f"🩹 AI Self-Healing Telemetry ({len(repairs)} Patches Applied)", expanded=True):
                                for r_idx, rep in enumerate(repairs, 1):
                                    badge_type = "badge-memory" if rep.get("cache_hit") else "badge-repaired"
                                    tag_text = "MEMORY REGISTRY (<1ms)" if rep.get("cache_hit") else f"ITERATION {rep.get('attempt', r_idx)} REPAIR"
                                    st.markdown(f"""
                                        <div class="healing-card">
                                            <span class="badge-tag {badge_type}">{tag_text}</span>
                                            <strong style="color: #F8FAFC; margin-left: 8px;">Source: {rep.get('model_used', 'AI Cascade')} &bull; Category: {rep.get('error_category', 'build_error')}</strong>
                                            <p style="color: #DDD6FE; font-size: 13px; margin: 8px 0;"><b>Diagnosis:</b> {rep.get('diagnosis', 'N/A')}</p>
                                            <p style="color: #A78BFA; font-size: 13px; margin-bottom: 8px;"><b>Fix Applied:</b> {rep.get('fix_description', 'N/A')}</p>
                                        </div>
                                    """, unsafe_allow_html=True)
                                    if rep.get("diff"):
                                        st.caption("Unified Patch Diff (Dockerfile.failed ➔ Dockerfile.repaired):")
                                        st.code(rep["diff"], language="diff")

                        st.markdown("---")
                        st.write(f"**VM Deployment Environment Setup:** {lab_data.get('vm_recommendation', 'N/A')}")
                        st.write(f"**Open Infrastructure target ports required:** `{lab_data.get('ports', [80])}`")
                        st.write(f"**Static System Credentials:** `{lab_data.get('credentials', 'Default')}`")

                        st.markdown("#### Execution Workflow Sequences")
                        for step in lab_data.get("installation_steps", []):
                            st.markdown(f"- {step}")
                        st.markdown("#### Post-Exploitation Verification Audits")
                        for check in lab_data.get("verification_steps", []):
                            st.markdown(f"- `{check}`")

            # ==================================================================
            # TIER 2: REMOTE SSH SANDBOXES (LINUX / WINDOWS / MACOS)
            # ==================================================================
            with tier_ssh:
                st.markdown("### 🖥️ Tri-OS Remote SSH Sandbox Engine")
                st.caption("Execute reproduction scripts on dedicated remote physical or virtual machines over SSH when vulnerabilities cannot run in containers (e.g. kernel flaws, Windows services, or macOS daemons).")

                sandboxes = ssh_sandbox.get_configured_sandboxes()
                target_choice = st.radio(
                    "Select Target Operating System Sandbox:",
                    ["linux", "windows", "macos"],
                    format_func=lambda x: {
                        "linux": "🐧 Linux Target Sandbox (Ubuntu / Debian / RHEL)",
                        "windows": "🪟 Windows Target Sandbox (Win 10/11 / Server)",
                        "macos": "🍎 macOS Target Sandbox (Darwin / Apple Silicon)"
                    }[x],
                    horizontal=True,
                    key="sel_ssh_target"
                )

                selected_cfg = sandboxes[target_choice]

                # Connection Status Box
                col_box, col_probe = st.columns([3, 1])
                with col_box:
                    if selected_cfg["configured"]:
                        st.markdown(f"""
                            <div class="sandbox-card">
                                <span class="badge-tag badge-ssh">CONFIGURED TARGET</span>
                                <strong style="color: #F8FAFC; margin-left: 8px;">{selected_cfg['name']} &bull; {selected_cfg['host']}:{selected_cfg['port']}</strong>
                                <div style="font-size: 13px; color: #94A3B8; margin-top: 6px;">
                                    User: <code>{selected_cfg['username']}</code> &bull; Shell: <code>{selected_cfg['default_shell']}</code>
                                    {f" &bull; Note: <em>{selected_cfg['custom_info']}</em>" if selected_cfg.get('custom_info') else ''}
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                            <div style="background: rgba(30, 41, 59, 0.6); border: 1px dashed rgba(245, 158, 11, 0.4); border-radius: 10px; padding: 12px 18px; margin-bottom: 12px;">
                                <span class="badge-tag badge-offline">UNCONFIGURED</span>
                                <strong style="color: #F8FAFC; margin-left: 8px;">{selected_cfg['name']} is not configured in .env</strong>
                                <p style="color: #CBD5E1; font-size: 13px; margin: 6px 0 0 0;">
                                    To enable this target, set in <code>.env</code>: <code>SANDBOX_{target_choice.upper()}_HOST</code>, <code>SANDBOX_{target_choice.upper()}_USER</code>, and <code>SANDBOX_{target_choice.upper()}_PASS</code>.
                                </p>
                            </div>
                        """, unsafe_allow_html=True)

                with col_probe:
                    probe_key = f"probe_{target_choice}"
                    if st.button(f"🔍 Probe {target_choice.title()} OS", key=f"btn_probe_{target_choice}", use_container_width=True):
                        with st.spinner("Connecting via SSH & fingerprinting operating system..."):
                            probe_res = ssh_sandbox.test_connection(target_choice)
                            st.session_state[probe_key] = probe_res
                            st.rerun()

                # Display Probe Fingerprint Results if available
                cached_probe = st.session_state.get(f"probe_{target_choice}")
                if cached_probe:
                    if cached_probe.get("connected"):
                        fp = cached_probe.get("fingerprint", {})
                        st.success(f"✅ Reachable! Detected: **{cached_probe.get('summary')}** &bull; Kernel: `{fp.get('kernel', 'N/A')}` &bull; Python: `{fp.get('python_version', 'N/A')}` &bull; Ping: `{cached_probe.get('latency_ms')}ms`")
                    else:
                        st.error(f"❌ Connection Failed: {cached_probe.get('error')}")

                st.markdown("---")
                st.markdown(f"#### 📜 Remote Reproduction Script ({target_choice.upper()})")

                # Prepare default script based on OS and AI blueprint
                lab_cached = st.session_state.get(f"lab_{cve_id}") or db.get_lab_blueprint(cve_id)
                default_script = ""
                if target_choice == "windows":
                    default_script = (
                        f"# Automated PowerShell Replication Script for {cve_id}\n"
                        f"# Target: Windows Remote Host\n\n"
                        f"Write-Host '[+] Initializing Vulnerability Environment for {cve_id}...' -ForegroundColor Cyan\n"
                    )
                    if lab_cached and lab_cached.get("installation_steps"):
                        for step in lab_cached["installation_steps"]:
                            default_script += f"Write-Host '[*] {step}'\n"
                    default_script += (
                        "\n# Service Verification Probe\n"
                        "Get-Service | Select-Object -First 5\n"
                        f"Write-Host '[+] Environment Staged for {cve_id}' -ForegroundColor Green\n"
                    )
                else:
                    default_script = (
                        f"#!/usr/bin/env bash\n"
                        f"# Automated Bash Replication Script for {cve_id}\n"
                        f"# Target: {target_choice.title()} Remote Host\n"
                        f"set -e\n\n"
                        f"echo '[+] Initializing Lab Replication for {cve_id}...'\n"
                    )
                    if lab_cached and lab_cached.get("installation_steps"):
                        for step in lab_cached["installation_steps"]:
                            clean_step = step.replace('"', '\\"')
                            default_script += f"echo '[*] {clean_step}'\n"
                    default_script += (
                        f"\necho '[+] Lab Environment Configuration Complete for {cve_id}.'\n"
                    )

                script_input = st.text_area(
                    "Execution Script Content (Editable):",
                    value=default_script,
                    height=200,
                    key=f"txt_script_{target_choice}"
                )

                if st.button(f"🚀 Deploy & Execute on {target_choice.title()} Sandbox", key=f"btn_exec_{target_choice}", use_container_width=True):
                    if not selected_cfg["configured"]:
                        st.warning(f"⚠️ {selected_cfg['name']} is unconfigured. Please define connection settings in .env first.")
                    else:
                        with st.status(f"Executing lab script on {selected_cfg['name']} ({selected_cfg['host']})...", expanded=True) as exec_box:
                            def progress(m):
                                exec_box.write(f"&bull; {m}")
                            progress("Establishing authenticated SSH tunnel...")
                            progress(f"Staging script on remote filesystem...")
                            exec_res = ssh_sandbox.execute_script(target_choice, script_input, cve_id=cve_id)

                            if exec_res.get("success"):
                                exec_box.update(label="Script Executed Successfully!", state="complete")
                                st.success(f"Execution Succeeded! (Exit Code: {exec_res.get('exit_code')} &bull; Runtime: {exec_res.get('duration_sec')}s)")
                            else:
                                exec_box.update(label="Execution Failed / Non-Zero Exit Code", state="error")
                                st.error(f"Execution Error: {exec_res.get('error', 'Script returned non-zero code.')}")

                            tab_out, tab_err = st.tabs(["Stdout Stream", "Stderr Stream"])
                            with tab_out:
                                st.code(exec_res.get("stdout") or "No stdout emitted.", language="text")
                            with tab_err:
                                st.code(exec_res.get("stderr") or "No stderr emitted.", language="text")

            # ==================================================================
            # TIER 3: LEGACY OS ARCHIVAL INTELLIGENCE & ISO FINDER
            # ==================================================================
            with tier_iso:
                st.markdown("### 💿 Legacy OS Archival Intelligence & ISO Finder")
                st.caption("When vulnerability requirements cannot be satisfied by Docker containers or the current remote machines (e.g. vintage Linux kernels < 3.x, retired glibc versions, or legacy Windows Server 2008/2012), automatically surface official archive mirror ISOs and VM hypervisor configurations.")

                matched_isos = os_archives.match_legacy_os(cve_data)
                st.markdown(f"#### 🎯 Recommended Historical Environments for `{cve_id}` ({len(matched_isos)} Matched)")

                for iso_item in matched_isos:
                    st.markdown(f"""
                        <div class="iso-card">
                            <span class="badge-tag badge-iso">ARCHIVE MIRROR VERIFIED</span>
                            <h4 style="margin: 8px 0; color: #FEF3C7;">💿 {iso_item['name']}</h4>
                            <div style="font-size: 13px; color: #FDE68A; margin-bottom: 8px;">
                                <strong>Kernel / Build:</strong> <code>{iso_item['kernel_version']}</code> &bull; 
                                <strong>Architecture:</strong> <code>{iso_item['architecture']}</code> &bull; 
                                <strong>Released:</strong> {iso_item['release_date']} &bull; 
                                <strong>EOL:</strong> {iso_item['eol_date']}
                            </div>
                            <div style="font-size: 12px; color: #CBD5E1; margin-bottom: 10px;">
                                <strong>Match Reason:</strong> {', '.join(iso_item.get('match_reasons', []))}
                            </div>
                            <a href="{iso_item['iso_url']}" target="_blank" style="display: inline-block; background: #D97706; color: #FFFFFF; font-weight: bold; padding: 6px 14px; border-radius: 6px; text-decoration: none; margin-right: 12px; font-size: 13px;">📥 Download ISO ({iso_item['distribution']})</a>
                            <a href="{iso_item['mirror_portal']}" target="_blank" style="color: #FBBF24; text-decoration: underline; font-size: 13px;">📂 Open Official Archive Directory</a>
                        </div>
                    """, unsafe_allow_html=True)

                    with st.expander(f"⚙️ View VM Hardware Profile & Archive Repository Config for {iso_item['name']}"):
                        vm_prof = iso_item.get("vm_profile", {})
                        col_vm1, col_vm2, col_vm3 = st.columns(3)
                        with col_vm1:
                            st.metric("Recommended RAM", f"{vm_prof.get('ram_mb', 2048)} MB")
                        with col_vm2:
                            st.metric("Virtual CPUs", f"{vm_prof.get('vcpus', 2)} Cores")
                        with col_vm3:
                            st.metric("Hard Disk Space", f"{vm_prof.get('disk_gb', 25)} GB")

                        st.markdown("**Network Containment:** `Host-Only Adapter (Isolated Lab Subnet)`")
                        if iso_item.get("apt_sources_snippet"):
                            st.markdown("**Archive Package Repository Configuration (Fix for 404 EOL Mirrors):**")
                            st.code(iso_item["apt_sources_snippet"], language="bash")

                        # Hypervisor copy-paste setup
                        guides = os_archives.get_setup_instructions(iso_item["id"])
                        if guides:
                            st.markdown("**Quick Setup Guide:**")
                            st.text(guides.get("virtualbox", ""))

                st.markdown("---")
                with st.expander("📚 Search Full Historical Operating System Catalog"):
                    search_q = st.text_input("Filter historical catalog (e.g. 'Ubuntu 14', 'Debian 8', 'CentOS 6', 'Windows 2008'):", key="iso_catalog_search")
                    catalog_results = os_archives.search_catalog(search_q)
                    st.caption(f"Showing {len(catalog_results)} historical OS releases")
                    for cat_item in catalog_results:
                        st.markdown(f"- **{cat_item['name']}** (`{cat_item['kernel_version']}`) &bull; [Direct ISO]({cat_item['iso_url']}) &bull; [Archive Mirror]({cat_item['mirror_portal']})")

        # --- TAB 4: POCS / BLOGS (Priority Order: Vulhub -> Feeds -> GitHub) ---
        with tab_pocs_blogs:
            st.subheader("Aggregated Proof-of-Concepts, Vulhub Environments & Technical Writeups")
            
            has_findings = False
            
            # Priority 1: Vulhub Prominent Display
            if vulhub_matches:
                has_findings = True
                for v_item in vulhub_matches:
                    st.markdown(f"""
                        <div class="vulhub-card">
                            <span class="badge-tag badge-vulhub">⭐ PRIORITY REPLICATION ENVIRONMENT</span>
                            <h4 style="margin: 8px 0; color: #F0F9FF;">🐳 {v_item['title']}</h4>
                            <p style="color: #BAE6FD; font-size: 13px; margin-bottom: 8px;">
                                Official Vulhub vulnerable Docker container lab verified for this CVE.
                            </p>
                            <a href="{v_item['url']}" target="_blank" style="color: #38BDF8; font-weight: bold; text-decoration: underline; margin-right: 15px;">📂 Open Vulhub Directory</a>
                            <a href="{v_item['docker_compose_url']}" target="_blank" style="color: #7DD3FC; text-decoration: underline;">📄 Raw docker-compose.yml</a>
                        </div>
                    """, unsafe_allow_html=True)
            
            # Priority 2: Exploit-DB, Rapid7 Metasploit, Nuclei Scanner Templates & Threat Blogs
            other_intel = [it for it in extra_intel if not it.get("is_vulhub")]
            if other_intel:
                has_findings = True
                grouped_sources = {}
                for item in other_intel:
                    src = item["source"]
                    grouped_sources.setdefault(src, []).append(item)
                
                for source_name, items in grouped_sources.items():
                    st.markdown(f"#### 🔍 {source_name}")
                    for item in items:
                        badge_name = item.get("badge", "INTEL")
                        badge_css = "badge-info"
                        if badge_name == "EXPLOIT-DB":
                            badge_css = "badge-edb"
                        elif badge_name == "METASPLOIT":
                            badge_css = "badge-metasploit"
                        elif badge_name == "RAPID7":
                            badge_css = "badge-rapid7"
                        elif badge_name == "NUCLEI":
                            badge_css = "badge-nuclei"
                        elif badge_name == "WRITEUP":
                            badge_css = "badge-writeup"
                        elif badge_name == "RESEARCH BLOG":
                            badge_css = "badge-vendor"
                        
                        st.markdown(f"<span class='badge-tag {badge_css}'>{badge_name}</span> [{item['title']}]({item['url']})", unsafe_allow_html=True)
                    st.markdown("---")

            # Priority 3 (Moved Down): GitHub PoC Repositories
            if github_pocs:
                has_findings = True
                st.markdown("#### 🐙 GitHub PoC Repositories")
                for poc in github_pocs:
                    st.markdown(f"⭐ **{poc.get('stars', 0)}** | <span class='badge-tag badge-poc'>POC</span> [{poc.get('title', 'PoC')}]({poc.get('url', '#')})", unsafe_allow_html=True)
                st.markdown("---")

            if not has_findings:
                st.info("No verified PoCs, Vulhub environments, or technical writeups found for this CVE.")
                    
        # --- TAB 5: REFERENCES (Expanded Authoritative References) ---
        with tab_refs:
            st.subheader("Authoritative Vendor Advisories, Standards & Verified Bulletins")
            st.caption("Surfacing NIST NVD, MITRE standards, vendor security bulletins, distribution errata, and threat research")
            if advisories:
                for idx, adv in enumerate(advisories, 1):
                    badge = adv.get("badge", "ADVISORY")
                    badge_css = "badge-vendor"
                    if any(k in badge for k in ["CISA", "CERT", "NIST", "MITRE"]):
                        badge_css = "badge-poc"
                    elif any(k in badge for k in ["ERRATA", "PATCH"]):
                        badge_css = "badge-rapid7"
                    elif any(k in badge for k in ["ZDI", "PACKET"]):
                        badge_css = "badge-edb"
                    elif any(k in badge for k in ["RESEARCH", "DISCLOSURE", "OSS"]):
                        badge_css = "badge-writeup"
                    elif any(k in badge for k in ["DEBIAN", "UBUNTU"]):
                        badge_css = "badge-nuclei"
                    
                    st.markdown(f"""
                        <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; padding: 12px 16px; margin-bottom: 10px;">
                            <span class='badge-tag {badge_css}'>{badge}</span>
                            <strong style="color: #F8FAFC; font-size: 14px;">{adv.get('title', 'Security Advisory')}</strong>
                            <div style="margin-top: 6px; font-size: 13px;">
                                <a href="{adv.get('url', '#')}" target="_blank" style="color: #38BDF8; word-break: break-all; text-decoration: underline;">{adv.get('url', '#')}</a>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("No authoritative vendor advisories or bulletins discovered for this CVE.")
                
        # --- TAB 6: DOWNLOADS ---
        with tab_downloads:
            st.subheader("Export Pipeline Engine Data Structure")
            current_lab = st.session_state.get(f"lab_{cve_id}", {})
            cached_ai = st.session_state.get(f"ai_intel_{cve_id}", {})
            json_dump = format_json_output(cve_data, github_pocs, extra_intel, cached_ai, current_lab)
            
            st.download_button(
                label="Download Enriched Platform Intelligence Profile (JSON)",
                data=json_dump,
                file_name=f"{cve_id}_ai_intel.json",
                mime="application/json"
            )
            st.json(json_dump)

        # --- TAB 7: DATABASE MANAGEMENT ---
        with tab_database:
            st.subheader("🗄️ Local SQLite Knowledge Base & Storage Metrics")
            st.caption(f"Database File: `vulnerability_intel.db` (SQLite 3 WAL Mode)")

            tab_db_stats = db.get_platform_stats()
            s_col1, s_col2, s_col3, s_col4, s_col5, s_col6, s_col7 = st.columns(7)
            s_col1.metric("CVEs Stored", tab_db_stats["total_cves"])
            s_col2.metric("GitHub PoCs", tab_db_stats["total_pocs"])
            s_col3.metric("Exploit Feeds", tab_db_stats["total_exploits"])
            s_col4.metric("Lab Blueprints", tab_db_stats["total_labs"])
            s_col5.metric("AI Briefings", tab_db_stats["total_ai_analyses"])
            s_col6.metric("Deployed Labs", tab_db_stats.get("total_deployed", 0))
            s_col7.metric("Error Memory", tab_db_stats.get("total_error_solutions", 0))

            # Deployed Labs Section
            deployed_list = db.get_all_deployed_labs()
            if deployed_list:
                st.markdown("---")
                st.markdown("#### 🐳 Active & Deployed Lab Environments")
                for dep in deployed_list:
                    d_col1, d_col2, d_col3, d_col4 = st.columns([2, 4, 2, 2])
                    with d_col1:
                        st.markdown(f"**`{dep['cve_id']}`**")
                        status_badge = "badge-active" if dep['status'] == 'running' else "badge-info"
                        st.markdown(f"<span class='badge-tag {status_badge}'>{dep['status'].upper()}</span>", unsafe_allow_html=True)
                    with d_col2:
                        st.write(f"Type: `{dep['deployment_type']}` &bull; Container: `{dep['container_name']}`")
                        st.caption(f"Health: `{dep['health_status']}` | Updated: {dep['updated_at']}")
                    with d_col3:
                        if dep.get('host_port'):
                            st.markdown(f"Port: [`{dep['host_port']}`](http://localhost:{dep['host_port']})")
                    with d_col4:
                        if dep['status'] == 'running':
                            if st.button("⏹️ Stop", key=f"stop_tab7_{dep['cve_id']}", use_container_width=True):
                                docker_mgr.stop_lab(dep['cve_id'])
                                st.rerun()
                        else:
                            if st.button("🗑️ Remove", key=f"rm_tab7_{dep['cve_id']}", use_container_width=True):
                                db.delete_lab_deployment(dep['cve_id'])
                                st.rerun()
                    st.markdown("<hr style='margin: 4px 0; border-color: rgba(255,255,255,0.05);'>", unsafe_allow_html=True)

            st.markdown("---")
            st.markdown("#### 📑 Stored Vulnerability Dossiers")
            all_saved = db.get_all_cves(limit=100)
            if all_saved:
                for item in all_saved:
                    col_id, col_info, col_sev, col_action = st.columns([2, 4, 2, 2])
                    with col_id:
                        st.markdown(f"**`{item['cve_id']}`**")
                        if item.get("is_kev"):
                            st.markdown("<span class='badge-tag badge-poc'>CISA KEV</span>", unsafe_allow_html=True)
                    with col_info:
                        st.write(f"{item.get('vendor', 'N/A')} - {item.get('product', 'N/A')}")
                        st.caption(f"Updated: {item.get('updated_at', 'N/A')}")
                    with col_sev:
                        st.markdown(f"`{item.get('cvss_severity', 'N/A')}` ({item.get('primary_v3_score', 'N/A')})")
                    with col_action:
                        if st.button("Open Dossier", key=f"open_db_{item['cve_id']}", use_container_width=True):
                            st.session_state.active_cve = item["cve_id"]
                            st.rerun()
                    st.markdown("<hr style='margin: 4px 0; border-color: rgba(255,255,255,0.05);'>", unsafe_allow_html=True)
            else:
                st.info("No CVE records stored in local database yet.")

            st.markdown("---")
            col_del1, col_del2 = st.columns([4, 2])
            with col_del2:
                if st.button("🗑️ Delete Current CVE from DB", key=f"del_{cve_id}", use_container_width=True):
                    db.delete_cve(cve_id)
                    st.success(f"Removed {cve_id} from local database.")
                    st.rerun()

# ==============================================================================
# WELCOME / EMPTY STATE DASHBOARD (When no CVE is searched yet)
# ==============================================================================
else:
    st.markdown("""
        <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 24px; margin-bottom: 24px;">
            <h3 style="margin-top: 0; color: #F8FAFC;">👋 Welcome to Vulnerability Lab Builder</h3>
            <p style="color: #94A3B8; font-size: 14px; line-height: 1.6;">
                Search any CVE identifier above (e.g. <code>CVE-2016-3088</code>, <code>CVE-2021-44228</code>, <code>CVE-2024-3400</code>) or simply click <b>Search CVE</b> with an empty search field to load a previously investigated vulnerability.
            </p>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("#### 🗄️ Locally Cached Vulnerabilities")
    all_stored = db.get_all_cves(limit=20)
    if all_stored:
        st.markdown("<p style='color: #94A3B8; font-size: 13px;'>The following vulnerabilities are saved in your local SQLite database for instant offline analysis:</p>", unsafe_allow_html=True)
        for row in all_stored:
            c1, c2, c3, c4 = st.columns([2, 4, 2, 2])
            with c1:
                st.markdown(f"**`{row['cve_id']}`**")
                if row.get("is_kev"):
                    st.markdown("<span class='badge-tag badge-poc'>CISA KEV</span>", unsafe_allow_html=True)
            with c2:
                st.write(f"{row.get('vendor', 'N/A')} - {row.get('product', 'N/A')}")
                st.caption(f"Cached: {row.get('updated_at', 'N/A')}")
            with c3:
                st.markdown(f"`{row.get('cvss_severity', 'N/A')}` ({row.get('primary_v3_score', 'N/A')})")
            with c4:
                if st.button("Inspect Dossier", key=f"welcome_open_{row['cve_id']}", use_container_width=True):
                    st.session_state.active_cve = row["cve_id"]
                    st.rerun()
            st.markdown("<hr style='margin: 4px 0; border-color: rgba(255,255,255,0.05);'>", unsafe_allow_html=True)
    else:
        st.info("No vulnerabilities stored in local database yet. Enter a CVE ID above or try a quick search below!")

    st.markdown("#### ⚡ Popular Pre-Configured Vulnerability Environments")
    sample_cves = [
        ("CVE-2016-3088", "Apache ActiveMQ Fileserver RCE (Vulhub Docker Lab)"),
        ("CVE-2021-44228", "Log4Shell Apache Log4j JNDI RCE"),
        ("CVE-2024-3400", "Palo Alto PAN-OS GlobalProtect Command Injection"),
        ("CVE-2023-46604", "Apache ActiveMQ OpenWire Protocol RCE")
    ]
    p_cols = st.columns(4)
    for idx, (s_cve, s_desc) in enumerate(sample_cves):
        with p_cols[idx]:
            st.markdown(f"""
                <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 10px; padding: 14px; min-height: 110px;">
                    <div style="font-weight: 700; color: #38BDF8; font-size: 14px; margin-bottom: 4px;">{s_cve}</div>
                    <div style="font-size: 12px; color: #94A3B8; margin-bottom: 10px;">{s_desc}</div>
                </div>
            """, unsafe_allow_html=True)
            if st.button(f"Load {s_cve}", key=f"btn_sample_{s_cve}", use_container_width=True):
                st.session_state.active_cve = s_cve
                st.rerun()
