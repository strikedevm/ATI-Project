import streamlit as st

def apply_custom_css():
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

        /* Hide the Streamlit sidebar completely */
        [data-testid="stSidebar"], section[data-testid="stSidebar"], [data-testid="collapsedControl"] {
            display: none !important;
        }

        /* Global Background - Rich Deep Cyber Navy with Ambient Gradients */
        .stApp {
            font-family: 'Plus Jakarta Sans', sans-serif !important;
            background: 
                radial-gradient(ellipse 90% 55% at 50% -15%, rgba(30, 58, 138, 0.35) 0%, transparent 70%),
                radial-gradient(ellipse 65% 45% at 85% 15%, rgba(99, 102, 241, 0.18) 0%, transparent 60%),
                radial-gradient(ellipse 55% 35% at 15% 25%, rgba(14, 165, 233, 0.16) 0%, transparent 55%),
                #070A12 !important;
            color: #F1F5F9 !important;
        }

        /* Main layout container */
        .main .block-container {
            max-width: 1320px !important;
            padding-top: 1.8rem !important;
            padding-bottom: 4rem !important;
        }

        /* Header Hero Banner */
        .header-hero {
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(30, 41, 59, 0.65) 100%);
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(20px);
            border-radius: 16px;
            padding: 22px 30px;
            margin-bottom: 24px;
            box-shadow: 0 10px 35px rgba(0, 0, 0, 0.45);
            display: flex;
            align-items: center;
            gap: 22px;
        }

        .header-hero-img {
            width: 74px;
            height: 74px;
            border-radius: 14px;
            box-shadow: 0 0 25px rgba(56, 189, 248, 0.45);
            border: 1.5px solid rgba(56, 189, 248, 0.6);
            object-fit: cover;
            flex-shrink: 0;
        }

        .hero-title {
            font-size: 32px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #FFFFFF 15%, #93C5FD 65%, #60A5FA 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 6px;
        }

        .hero-subtitle {
            font-size: 14px;
            color: #94A3B8;
            font-weight: 400;
            letter-spacing: 0.2px;
        }

        /* Search Form Card */
        div[data-testid="stForm"] {
            background: rgba(15, 23, 42, 0.8) !important;
            border: 1px solid rgba(56, 189, 248, 0.25) !important;
            border-radius: 14px !important;
            padding: 18px 22px !important;
            backdrop-filter: blur(16px) !important;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4) !important;
            margin-bottom: 16px !important;
        }

        div[data-testid="stForm"]:focus-within {
            border-color: #38BDF8 !important;
            box-shadow: 0 0 25px rgba(56, 189, 248, 0.28) !important;
        }

        /* Text Input */
        div[data-testid="stTextInput"] input {
            background: rgba(11, 15, 25, 0.9) !important;
            border: 1px solid rgba(255, 255, 255, 0.12) !important;
            border-radius: 10px !important;
            color: #F8FAFC !important;
            font-size: 15px !important;
            font-weight: 500 !important;
            padding: 12px 18px !important;
            font-family: 'JetBrains Mono', monospace !important;
        }

        div[data-testid="stTextInput"] input:focus {
            border-color: #38BDF8 !important;
            box-shadow: 0 0 14px rgba(56, 189, 248, 0.35) !important;
        }

        /* Primary Search Button */
        button[kind="primaryFormSubmit"], button[kind="primary"] {
            background: linear-gradient(135deg, #2563EB 0%, #4F46E5 100%) !important;
            border: 1px solid rgba(255, 255, 255, 0.18) !important;
            color: #FFFFFF !important;
            border-radius: 10px !important;
            font-weight: 700 !important;
            font-size: 14px !important;
            padding: 12px 24px !important;
            box-shadow: 0 4px 18px rgba(37, 99, 235, 0.4) !important;
            transition: all 0.2s ease !important;
        }

        button[kind="primaryFormSubmit"]:hover, button[kind="primary"]:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 6px 24px rgba(37, 99, 235, 0.6) !important;
        }

        /* Secondary Action Buttons & Chips */
        button[kind="secondary"] {
            background: rgba(30, 41, 59, 0.75) !important;
            border: 1px solid rgba(56, 189, 248, 0.25) !important;
            color: #E2E8F0 !important;
            border-radius: 8px !important;
            font-size: 13px !important;
            font-weight: 600 !important;
            padding: 7px 14px !important;
            transition: all 0.2s ease !important;
        }

        button[kind="secondary"]:hover {
            background: rgba(56, 189, 248, 0.18) !important;
            border-color: #38BDF8 !important;
            color: #38BDF8 !important;
            box-shadow: 0 0 14px rgba(56, 189, 248, 0.35) !important;
            transform: translateY(-1px) !important;
        }

        /* Top Metric Cards */
        .metric-card {
            background: rgba(15, 23, 42, 0.75);
            border: 1px solid rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(14px);
            padding: 14px 8px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            transition: transform 0.2s ease, border-color 0.2s ease;
            min-height: 105px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            overflow: hidden;
            word-break: break-word;
            overflow-wrap: anywhere;
        }

        .metric-card:hover {
            transform: translateY(-3px);
            border-color: rgba(56, 189, 248, 0.35);
        }

        .metric-title {
            font-size: 11px;
            letter-spacing: 1px;
            color: #94A3B8;
            text-transform: uppercase;
            font-weight: 600;
            margin-bottom: 6px;
        }

        .metric-value {
            font-size: 18px;
            font-weight: 800;
            color: #F8FAFC;
            letter-spacing: -0.3px;
            line-height: 1.25;
            word-break: break-word;
            overflow-wrap: anywhere;
            max-width: 100%;
        }

        .metric-value-sm {
            font-size: 14px !important;
            font-weight: 700 !important;
            line-height: 1.25 !important;
        }

        .metric-value-xs {
            font-size: 11.5px !important;
            font-weight: 700 !important;
            line-height: 1.2 !important;
            letter-spacing: 0 !important;
        }

        /* Tabs Navigation */
        .stTabs [data-baseweb="tab-list"] {
            background-color: rgba(15, 23, 42, 0.7) !important;
            border-radius: 12px !important;
            padding: 6px !important;
            gap: 8px !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            backdrop-filter: blur(12px) !important;
        }

        .stTabs [data-baseweb="tab"] {
            border-radius: 8px !important;
            padding: 8px 18px !important;
            color: #94A3B8 !important;
            font-weight: 600 !important;
            font-size: 14px !important;
            transition: all 0.2s ease !important;
        }

        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, rgba(37, 99, 235, 0.28) 0%, rgba(99, 102, 241, 0.28) 100%) !important;
            color: #60A5FA !important;
            border: 1px solid rgba(96, 165, 250, 0.35) !important;
        }

        /* AI Assessment Card */
        .ai-box {
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-left: 5px solid #6366F1;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 18px;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
        }

        /* Vulhub Priority Card */
        .vulhub-card {
            background: linear-gradient(135deg, rgba(8, 47, 73, 0.85) 0%, rgba(12, 74, 110, 0.7) 100%);
            border: 1px solid #0284C7;
            border-left: 5px solid #38BDF8;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 18px;
            box-shadow: 0 8px 24px rgba(2, 132, 199, 0.25);
        }

        /* Badges */
        .badge-tag {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            margin-right: 6px;
            margin-bottom: 6px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }
        .badge-vulhub {
            background-color: rgba(14, 165, 233, 0.25);
            color: #38BDF8;
            border: 1px solid #0EA5E9;
            font-weight: 800;
        }
        .badge-edb {
            background-color: rgba(249, 115, 22, 0.25);
            color: #FB923C;
            border: 1px solid #F97316;
        }
        .badge-metasploit {
            background-color: rgba(168, 85, 247, 0.25);
            color: #C084FC;
            border: 1px solid #A855F7;
        }
        .badge-nuclei {
            background-color: rgba(16, 185, 129, 0.25);
            color: #34D399;
            border: 1px solid #10B981;
        }
        .badge-poc {
            background-color: rgba(239, 68, 68, 0.2);
            color: #F87171;
            border: 1px solid #EF4444;
        }
        .badge-vendor {
            background-color: rgba(59, 130, 246, 0.2);
            color: #60A5FA;
            border: 1px solid #3B82F6;
        }
        .badge-info {
            background-color: rgba(100, 116, 139, 0.2);
            color: #94A3B8;
            border: 1px solid #64748B;
        }
        .badge-rapid7 {
            background-color: rgba(244, 63, 94, 0.2);
            color: #FB7185;
            border: 1px solid #F43F5E;
        }
        .badge-writeup {
            background-color: rgba(234, 179, 8, 0.2);
            color: #FACC15;
            border: 1px solid #EAB308;
        }
        </style>
    """, unsafe_allow_html=True)
