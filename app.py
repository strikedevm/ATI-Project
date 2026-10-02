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

        # --- TAB 3: LAB BUILDER ---
        with tab_lab:
            st.subheader("AI Automated Replication Sandbox Blueprint")
            st.caption("Synthesizes Dockerfile blueprints and validation workflows via Multi-Provider Cascade")
            
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
            
            lab_key = f"lab_{cve_id}"
            if lab_key not in st.session_state:
                cached_lab_db = db.get_lab_blueprint(cve_id)
                if cached_lab_db:
                    st.session_state[lab_key] = cached_lab_db

            if st.button("Generate Lab Configuration Engine", key="btn_gen_lab"):
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
                    st.code(lab_data.get("docker_recommendation", "# No docker snippet returned"), language="dockerfile", line_numbers=True)
                    st.write(f"**VM Deployment Environment Setup:** {lab_data.get('vm_recommendation', 'N/A')}")
                    st.write(f"**Open Infrastructure target ports required:** `{lab_data.get('ports', [80])}`")
                    st.write(f"**Static System Credentials:** `{lab_data.get('credentials', 'Default')}`")
                    
                    st.markdown("#### Execution Workflow Sequences")
                    for step in lab_data.get("installation_steps", []):
                        st.markdown(f"- {step}")
                    st.markdown("#### Post-Exploitation Verification Audits")
                    for check in lab_data.get("verification_steps", []):
                        st.markdown(f"- `{check}`")

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
            s_col1, s_col2, s_col3, s_col4, s_col5 = st.columns(5)
            s_col1.metric("CVEs Stored", tab_db_stats["total_cves"])
            s_col2.metric("GitHub PoCs", tab_db_stats["total_pocs"])
            s_col3.metric("Exploit Feeds", tab_db_stats["total_exploits"])
            s_col4.metric("Lab Blueprints", tab_db_stats["total_labs"])
            s_col5.metric("AI Briefings", tab_db_stats["total_ai_analyses"])

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
