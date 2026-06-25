"""
AI-Powered Security Operations Platform
SOC Dashboard — Threat Detection, Alert Triage, Incident Investigation & Vulnerability Assessment
"""

import os
import re
import ssl
import json
import time
import socket
import hashlib
import datetime
import warnings
import traceback
import urllib.parse
from io import BytesIO

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import requests
import streamlit as st
import whois
import xgboost as xgb

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────
# GLOBAL CSS — dark SOC theme
# ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600;700&display=swap');

/* ── Root palette ── */
:root {
    --bg-base:       #0a0d12;
    --bg-panel:      #111520;
    --bg-card:       #161b27;
    --bg-card-hover: #1c2235;
    --border:        #232a3b;
    --border-accent: #2d3650;
    --text-primary:  #e4e8f0;
    --text-secondary:#8a95b0;
    --text-muted:    #4f5a72;
    --accent-blue:   #3d8ef0;
    --accent-cyan:   #00d4ff;
    --accent-green:  #22d89a;
    --accent-orange: #f97316;
    --accent-red:    #ef4444;
    --accent-yellow: #fbbf24;
    --accent-purple: #a855f7;
    --glow-blue:     rgba(61,142,240,0.15);
    --glow-green:    rgba(34,216,154,0.12);
    --glow-red:      rgba(239,68,68,0.12);
}

/* ── App shell ── */
.stApp, .stMain, .block-container {
    background-color: var(--bg-base) !important;
    color: var(--text-primary) !important;
}
.block-container { padding: 1.5rem 2rem !important; max-width: 1400px; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: var(--bg-panel) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { color: var(--text-primary) !important; }

/* ── Hide Streamlit chrome ── */
#MainMenu, footer, header { visibility: hidden; }
[data-testid="stToolbar"] { display: none; }

/* ── Typography ── */
h1, h2, h3, h4 { font-family: 'Inter', sans-serif !important; letter-spacing: -0.02em; }
code, pre { font-family: 'JetBrains Mono', monospace !important; }

/* ── KPI Cards ── */
.kpi-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
.kpi-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.2rem 1.4rem;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s, transform 0.2s;
}
.kpi-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
}
.kpi-card.blue::before  { background: var(--accent-blue);   box-shadow: 0 0 12px var(--accent-blue); }
.kpi-card.red::before   { background: var(--accent-red);    box-shadow: 0 0 12px var(--accent-red);  }
.kpi-card.orange::before{ background: var(--accent-orange); box-shadow: 0 0 12px var(--accent-orange); }
.kpi-card.green::before { background: var(--accent-green);  box-shadow: 0 0 12px var(--accent-green); }
.kpi-card.purple::before{ background: var(--accent-purple); box-shadow: 0 0 12px var(--accent-purple); }
.kpi-label { font-size: 0.72rem; font-weight: 500; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.4rem; }
.kpi-value { font-size: 2rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; line-height: 1; }
.kpi-sub   { font-size: 0.72rem; color: var(--text-muted); margin-top: 0.3rem; }
.kpi-card.blue   .kpi-value { color: var(--accent-blue); }
.kpi-card.red    .kpi-value { color: var(--accent-red);  }
.kpi-card.orange .kpi-value { color: var(--accent-orange); }
.kpi-card.green  .kpi-value { color: var(--accent-green); }
.kpi-card.purple .kpi-value { color: var(--accent-purple); }

/* ── Section headers ── */
.section-header {
    display: flex; align-items: center; gap: 0.6rem;
    font-family: 'Inter', sans-serif;
    font-size: 0.8rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.1em;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.6rem;
    margin: 1.5rem 0 1rem;
}
.section-header .dot { width: 6px; height: 6px; border-radius: 50%; }

/* ── Panel cards ── */
.panel {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.4rem 1.6rem;
    margin-bottom: 1rem;
}

/* ── Risk badges ── */
.badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-family: 'JetBrains Mono', monospace;
}
.badge-critical { background: rgba(239,68,68,0.15);  color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }
.badge-high     { background: rgba(249,115,22,0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.3); }
.badge-medium   { background: rgba(251,191,36,0.15); color: #fbbf24; border: 1px solid rgba(251,191,36,0.3); }
.badge-low      { background: rgba(34,216,154,0.15); color: #22d89a; border: 1px solid rgba(34,216,154,0.3); }
.badge-info     { background: rgba(61,142,240,0.15); color: #3d8ef0; border: 1px solid rgba(61,142,240,0.3); }

/* ── Finding rows ── */
.finding-row {
    display: flex; justify-content: space-between; align-items: flex-start;
    padding: 0.8rem 0;
    border-bottom: 1px solid var(--border);
    gap: 1rem;
}
.finding-row:last-child { border-bottom: none; }
.finding-title { font-size: 0.88rem; font-weight: 500; color: var(--text-primary); margin-bottom: 0.2rem; }
.finding-desc  { font-size: 0.78rem; color: var(--text-secondary); }

/* ── SHAP bars ── */
.shap-row { display: flex; align-items: center; gap: 0.8rem; margin: 0.5rem 0; }
.shap-label { font-size: 0.8rem; color: var(--text-secondary); width: 240px; flex-shrink: 0; font-family: 'JetBrains Mono', monospace; }
.shap-bar-wrap { flex: 1; background: var(--bg-panel); border-radius: 4px; height: 12px; overflow: hidden; }
.shap-bar-pos { height: 100%; background: linear-gradient(90deg, #ef4444, #f97316); border-radius: 4px; transition: width 0.6s; }
.shap-bar-neg { height: 100%; background: linear-gradient(90deg, #22d89a, #3d8ef0); border-radius: 4px; transition: width 0.6s; }
.shap-val { font-size: 0.78rem; font-family: 'JetBrains Mono', monospace; width: 60px; text-align: right; }
.shap-val.pos { color: var(--accent-red); }
.shap-val.neg { color: var(--accent-green); }

/* ── URL input styling ── */
.stTextInput input {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-accent) !important;
    border-radius: 8px !important;
    color: var(--text-primary) !important;
    font-family: 'JetBrains Mono', monospace !important;
}
.stTextInput input:focus {
    border-color: var(--accent-blue) !important;
    box-shadow: 0 0 0 2px var(--glow-blue) !important;
}

/* ── Buttons ── */
.stButton button {
    background: linear-gradient(135deg, #1a3a6b, #0f2347) !important;
    border: 1px solid var(--accent-blue) !important;
    color: var(--accent-cyan) !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    border-radius: 8px !important;
    letter-spacing: 0.03em !important;
    transition: all 0.2s !important;
}
.stButton button:hover {
    background: linear-gradient(135deg, #2050a0, #1a3a6b) !important;
    box-shadow: 0 0 20px var(--glow-blue) !important;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: var(--bg-panel) !important;
    border-radius: 8px !important;
    padding: 0.2rem !important;
    gap: 0.2rem !important;
    border-bottom: 1px solid var(--border) !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: var(--text-secondary) !important;
    border-radius: 6px !important;
    font-size: 0.82rem !important;
    font-weight: 500 !important;
    padding: 0.5rem 1rem !important;
}
.stTabs [aria-selected="true"] {
    background: var(--bg-card) !important;
    color: var(--accent-cyan) !important;
    border: 1px solid var(--border-accent) !important;
}

/* ── Progress bar ── */
.stProgress > div > div { background: var(--accent-blue) !important; border-radius: 4px; }

/* ── Metric ── */
[data-testid="stMetricValue"] { color: var(--text-primary) !important; }
[data-testid="stMetricLabel"] { color: var(--text-secondary) !important; }

/* ── Dataframe ── */
.stDataFrame { border: 1px solid var(--border) !important; border-radius: 8px !important; }

/* ── Expander ── */
details { background: var(--bg-card) !important; border: 1px solid var(--border) !important; border-radius: 8px !important; }
summary { color: var(--text-primary) !important; }

/* ── Alert boxes ── */
.alert-critical { background: rgba(239,68,68,0.08); border-left: 3px solid #ef4444; border-radius: 6px; padding: 1rem; margin: 0.5rem 0; }
.alert-high     { background: rgba(249,115,22,0.08); border-left: 3px solid #f97316; border-radius: 6px; padding: 1rem; margin: 0.5rem 0; }
.alert-medium   { background: rgba(251,191,36,0.08); border-left: 3px solid #fbbf24; border-radius: 6px; padding: 1rem; margin: 0.5rem 0; }
.alert-low      { background: rgba(34,216,154,0.08); border-left: 3px solid #22d89a; border-radius: 6px; padding: 1rem; margin: 0.5rem 0; }

/* ── Logo / brand ── */
.brand-logo {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--accent-cyan);
    letter-spacing: 0.05em;
}
.brand-sub { font-size: 0.65rem; color: var(--text-muted); letter-spacing: 0.12em; text-transform: uppercase; }

/* ── Status dot ── */
.status-live { display: inline-flex; align-items: center; gap: 0.4rem; font-size: 0.72rem; color: var(--accent-green); }
.status-dot  { width: 6px; height: 6px; border-radius: 50%; background: var(--accent-green); box-shadow: 0 0 6px var(--accent-green); animation: pulse 2s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-base); }
::-webkit-scrollbar-thumb { background: var(--border-accent); border-radius: 3px; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────
def init_state():
    defaults = {
        "assessments": [],
        "model": None,
        "model_loaded": False,
        "scan_result": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()


# ─────────────────────────────────────────────────────────────
# FEATURE DEFINITIONS  (must match model training order)
# ─────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_digits",
    "num_special_chars",
    "has_https",
    "has_ip_address",
    "has_at_symbol",
    "has_double_slash",
    "has_suspicious_tld",
    "subdomain_depth",
    "path_depth",
    "has_port",
    "has_query_params",
    "num_query_params",
    "has_fragment",
    "url_entropy",
    "ssl_valid",
    "ssl_days_remaining",
    "domain_age_days",
    "is_new_domain",
    "missing_hsts",
    "missing_csp",
    "missing_xframe",
    "missing_xcontent",
    "missing_referrer",
    "has_open_redirect",
    "phishing_keywords",
    "suspicious_pattern_score",
    "redirect_count",
]

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc",
    ".top", ".club", ".work", ".party", ".date", ".faith",
    ".review", ".stream", ".download", ".link", ".click",
}

PHISHING_KEYWORDS = [
    "login", "signin", "account", "update", "verify", "secure",
    "bank", "paypal", "ebay", "amazon", "netflix", "apple",
    "password", "confirm", "suspend", "unlock", "recover",
    "wallet", "crypto", "urgent", "limited", "free", "prize",
]

SUSPICIOUS_PATTERNS = [
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # IP in URL
    r"--[a-z]",                                 # double-dash trick
    r"[a-z]@[a-z]",                             # @ in URL
    r"paypal.*\.(?!com)",                       # brand in wrong domain
    r"(?:secure|login|account).*-[a-z]+\.",     # secure-fake pattern
]


# ─────────────────────────────────────────────────────────────
# MODEL LOADING / CREATION
# ─────────────────────────────────────────────────────────────
def load_or_create_model():
    model_path = "Threat_Detection_XGBoost.pkl"
    if os.path.exists(model_path):
        import pickle
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        st.session_state["model_source"] = "Loaded from Threat_Detection_XGBoost.pkl"
    else:
        model = _create_demo_model()
        st.session_state["model_source"] = "Demo model (upload Threat_Detection_XGBoost.pkl for production)"
    st.session_state["model"] = model
    st.session_state["model_loaded"] = True
    return model


def _create_demo_model():
    """
    Creates a realistic demo XGBoost classifier tuned to the URL feature space
    when the production model file is not present.
    """
    np.random.seed(42)
    n = 3000
    X = np.zeros((n, len(FEATURE_NAMES)))

    # Simulate low-risk samples (class 0)
    low = n // 3
    med = n // 3

    # Low risk
    X[:low, 0]  = np.random.normal(35, 8, low)       # url_length
    X[:low, 7]  = 1                                    # has_https
    X[:low, 19] = 1                                    # ssl_valid
    X[:low, 20] = np.random.uniform(60, 365, low)     # ssl_days_remaining
    X[:low, 21] = np.random.uniform(365, 3650, low)   # domain_age_days

    # Medium risk
    X[low:low+med, 0]  = np.random.normal(60, 15, med)
    X[low:low+med, 7]  = np.random.choice([0, 1], med, p=[0.3, 0.7])
    X[low:low+med, 19] = np.random.choice([0, 1], med, p=[0.4, 0.6])
    X[low:low+med, 21] = np.random.uniform(30, 365, med)
    X[low:low+med, 23:28] = np.random.choice([0, 1], (med, 5), p=[0.4, 0.6])

    # High risk
    hi_start = low + med
    hi = n - hi_start
    X[hi_start:, 0]  = np.random.normal(90, 20, hi)
    X[hi_start:, 7]  = 0
    X[hi_start:, 19] = 0
    X[hi_start:, 21] = np.random.uniform(0, 30, hi)
    X[hi_start:, 22] = 1
    X[hi_start:, 23:28] = 1
    X[hi_start:, 28] = 1
    X[hi_start:, 29] = np.random.randint(2, 5, hi)
    X[hi_start:, 30] = np.random.uniform(0.5, 1.0, hi)

    X = np.clip(X, 0, None)
    y = np.array([0]*low + [1]*med + [2]*hi)

    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="mlogloss",
        verbosity=0,
        random_state=42,
    )
    # XGBoost v3: pass DataFrame to capture feature names automatically
    df_train = pd.DataFrame(X, columns=FEATURE_NAMES)
    model.fit(df_train, y)
    return model


# ─────────────────────────────────────────────────────────────
# URL FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────
def extract_url_features(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path   = parsed.path
    query  = parsed.query
    fragment = parsed.fragment

    # Basic counts
    feat = {}
    feat["url_length"]         = len(url)
    feat["domain_length"]      = len(domain)
    feat["num_dots"]            = url.count(".")
    feat["num_hyphens"]         = url.count("-")
    feat["num_underscores"]     = url.count("_")
    feat["num_digits"]          = sum(c.isdigit() for c in url)
    feat["num_special_chars"]   = sum(c in "@#!%&*=<>|" for c in url)
    feat["has_https"]           = 1 if parsed.scheme == "https" else 0
    feat["has_ip_address"]      = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.split(":")[0]) else 0
    feat["has_at_symbol"]       = 1 if "@" in url else 0
    feat["has_double_slash"]    = 1 if "//" in path else 0
    feat["has_suspicious_tld"]  = 1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS) else 0
    feat["subdomain_depth"]     = max(0, len(domain.split(".")) - 2)
    feat["path_depth"]          = len([p for p in path.split("/") if p])
    feat["has_port"]            = 1 if ":" in domain else 0
    feat["has_query_params"]    = 1 if query else 0
    feat["num_query_params"]    = len(urllib.parse.parse_qs(query))
    feat["has_fragment"]        = 1 if fragment else 0

    # Shannon entropy of URL
    s = url
    freq = {c: s.count(c)/len(s) for c in set(s)} if s else {}
    feat["url_entropy"] = -sum(p * np.log2(p) for p in freq.values() if p > 0)

    # These are filled later by live checks
    feat["ssl_valid"]          = 0
    feat["ssl_days_remaining"] = 0
    feat["domain_age_days"]    = 365   # default fallback
    feat["is_new_domain"]      = 0

    # Security headers (filled later)
    feat["missing_hsts"]      = 1
    feat["missing_csp"]       = 1
    feat["missing_xframe"]    = 1
    feat["missing_xcontent"]  = 1
    feat["missing_referrer"]  = 1

    # Advanced signals
    feat["has_open_redirect"]  = 1 if re.search(r"(redirect|url|return|next|goto)=http", url, re.I) else 0
    kw_matches = sum(kw in url.lower() for kw in PHISHING_KEYWORDS)
    feat["phishing_keywords"]  = kw_matches
    pat_score = sum(1 for p in SUSPICIOUS_PATTERNS if re.search(p, url, re.I))
    feat["suspicious_pattern_score"] = pat_score / len(SUSPICIOUS_PATTERNS)
    feat["redirect_count"]     = 0

    return feat


# ─────────────────────────────────────────────────────────────
# LIVE CHECKS
# ─────────────────────────────────────────────────────────────
def check_ssl(hostname: str, feat: dict) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                exp_str = cert.get("notAfter", "")
                try:
                    exp_dt = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_dt - datetime.datetime.utcnow()).days
                except Exception:
                    days_left = 0
                feat["ssl_valid"]          = 1
                feat["ssl_days_remaining"] = max(0, days_left)
                return {"valid": True, "days_remaining": days_left, "cert": cert}
    except Exception as e:
        feat["ssl_valid"]          = 0
        feat["ssl_days_remaining"] = 0
        return {"valid": False, "error": str(e)}


def check_headers(url: str, feat: dict) -> dict:
    findings = {}
    redirect_count = 0
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (CyberShield-SOC/2.0)"})
        redirect_count = len(resp.history)
        h = {k.lower(): v for k, v in resp.headers.items()}

        feat["missing_hsts"]      = 0 if "strict-transport-security" in h else 1
        feat["missing_csp"]       = 0 if "content-security-policy" in h else 1
        feat["missing_xframe"]    = 0 if "x-frame-options" in h else 1
        feat["missing_xcontent"]  = 0 if "x-content-type-options" in h else 1
        feat["missing_referrer"]  = 0 if "referrer-policy" in h else 1
        feat["redirect_count"]    = redirect_count

        findings = {
            "status_code":    resp.status_code,
            "hsts":           h.get("strict-transport-security", "MISSING"),
            "csp":            h.get("content-security-policy", "MISSING")[:80] if "content-security-policy" in h else "MISSING",
            "x_frame":        h.get("x-frame-options", "MISSING"),
            "x_content":      h.get("x-content-type-options", "MISSING"),
            "referrer":       h.get("referrer-policy", "MISSING"),
            "server":         h.get("server", "Unknown"),
            "redirect_count": redirect_count,
            "final_url":      resp.url,
        }
    except Exception as e:
        findings["error"] = str(e)
    return findings


def check_whois(domain: str, feat: dict) -> dict:
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            age = (datetime.datetime.now() - created).days
            feat["domain_age_days"] = max(0, age)
            feat["is_new_domain"]   = 1 if age < 30 else 0
        return {
            "registrar":    getattr(w, "registrar", "Unknown"),
            "created":      str(created)[:10] if created else "Unknown",
            "expires":      str(getattr(w, "expiration_date", "Unknown"))[:10],
            "country":      getattr(w, "country", "Unknown"),
            "name_servers": getattr(w, "name_servers", []),
            "age_days":     feat.get("domain_age_days", 0),
        }
    except Exception as e:
        return {"error": str(e), "age_days": feat.get("domain_age_days", 0)}


# ─────────────────────────────────────────────────────────────
# PREDICTION + SHAP
# ─────────────────────────────────────────────────────────────
def predict(model, feat_dict: dict):
    df = pd.DataFrame([feat_dict])[FEATURE_NAMES]
    proba = model.predict_proba(df)[0]
    pred  = int(np.argmax(proba))
    labels = ["Low Risk", "Medium Risk", "High Risk"]
    return {
        "class":      pred,
        "label":      labels[pred],
        "confidence": float(proba[pred]),
        "probabilities": {labels[i]: float(proba[i]) for i in range(3)},
        "features":   df,
    }


def compute_shap(model, feat_df: pd.DataFrame):
    try:
        import shap as _shap
        exp = _shap.TreeExplainer(model)
        sv  = exp.shap_values(feat_df)
        # XGBoost v3: sv shape is (samples, features, classes)
        sv_arr = np.array(sv)
        if sv_arr.ndim == 3:
            sv_arr = sv_arr.transpose(2, 0, 1)   # -> (classes, samples, features)
        return sv_arr, exp.expected_value
    except Exception:
        return None, None


# ─────────────────────────────────────────────────────────────
# VULNERABILITY RULES
# ─────────────────────────────────────────────────────────────
VULN_RULES = [
    # (severity, title, description, check_fn)
    ("critical", "Possible SQL Injection Vector",
     "URL contains query parameters that may be injectable.",
     lambda f, h: bool(re.search(r"(id|uid|user|pass|query|search|cat|article)=", f.get("url", ""), re.I)
                       and f.get("has_query_params"))),
    ("critical", "IP Address in URL",
     "Domain is a raw IP address — typical in phishing and C2 infrastructure.",
     lambda f, h: f.get("has_ip_address") == 1),
    ("high", "Missing HTTP Strict Transport Security (HSTS)",
     "Server does not enforce HTTPS via HSTS header, enabling downgrade attacks.",
     lambda f, h: f.get("missing_hsts") == 1),
    ("high", "Missing Content Security Policy",
     "No CSP header detected. XSS attacks may succeed without restriction.",
     lambda f, h: f.get("missing_csp") == 1),
    ("high", "Invalid or Expired SSL Certificate",
     "SSL certificate is invalid, expired, or not present.",
     lambda f, h: f.get("ssl_valid") == 0),
    ("high", "Suspicious TLD",
     f"Domain uses a TLD commonly associated with malicious activity.",
     lambda f, h: f.get("has_suspicious_tld") == 1),
    ("high", "Open Redirect Detected",
     "URL contains a redirect parameter pointing to an external resource.",
     lambda f, h: f.get("has_open_redirect") == 1),
    ("high", "Newly Registered Domain (< 30 days)",
     "Domain was registered very recently — a strong phishing indicator.",
     lambda f, h: f.get("is_new_domain") == 1),
    ("medium", "Missing X-Frame-Options",
     "Clickjacking attacks may be possible without the X-Frame-Options header.",
     lambda f, h: f.get("missing_xframe") == 1),
    ("medium", "Missing X-Content-Type-Options",
     "MIME-sniffing attacks are possible without nosniff directive.",
     lambda f, h: f.get("missing_xcontent") == 1),
    ("medium", "Missing Referrer-Policy",
     "Sensitive URL fragments may leak via Referer header to third parties.",
     lambda f, h: f.get("missing_referrer") == 1),
    ("medium", "Phishing Keywords Detected",
     "URL contains terms frequently used in credential phishing campaigns.",
     lambda f, h: f.get("phishing_keywords", 0) >= 2),
    ("medium", "Excessive Redirects",
     "URL chain involves multiple redirects, obscuring final destination.",
     lambda f, h: f.get("redirect_count", 0) > 2),
    ("medium", "High URL Entropy",
     "URL entropy suggests random/obfuscated path, possible encoded payload.",
     lambda f, h: f.get("url_entropy", 0) > 4.5),
    ("low", "No HTTPS",
     "Connection is over plain HTTP — data in transit is unencrypted.",
     lambda f, h: f.get("has_https") == 0),
    ("low", "Excessive Subdomain Depth",
     "Deep subdomain structure may indicate domain-shadowing technique.",
     lambda f, h: f.get("subdomain_depth", 0) >= 3),
    ("low", "SSL Certificate Expiring Soon (< 30 days)",
     "Certificate will expire within 30 days — service disruption risk.",
     lambda f, h: 0 < f.get("ssl_days_remaining", 0) < 30),
    ("low", "Suspicious URL Patterns",
     "URL matches one or more suspicious structural patterns.",
     lambda f, h: f.get("suspicious_pattern_score", 0) > 0),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def evaluate_vulnerabilities(feat_dict: dict, header_data: dict) -> list:
    results = []
    url = st.session_state.get("_current_url", "")
    feat_dict["url"] = url
    for sev, title, desc, fn in VULN_RULES:
        try:
            if fn(feat_dict, header_data):
                results.append({"severity": sev, "title": title, "description": desc})
        except Exception:
            pass
    results.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))
    return results


# ─────────────────────────────────────────────────────────────
# PDF REPORT GENERATION
# ─────────────────────────────────────────────────────────────
def generate_pdf_report(url, scan_ts, features, prediction, vulns, shap_data):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable, KeepTogether)

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)

    # Colors
    DARK   = colors.HexColor("#0a0d12")
    PANEL  = colors.HexColor("#161b27")
    ACCENT = colors.HexColor("#3d8ef0")
    GREEN  = colors.HexColor("#22d89a")
    RED    = colors.HexColor("#ef4444")
    ORANGE = colors.HexColor("#f97316")
    YELLOW = colors.HexColor("#fbbf24")
    TEXT   = colors.HexColor("#e4e8f0")
    MUTED  = colors.HexColor("#8a95b0")

    SEV_COLORS = {"critical": RED, "high": ORANGE, "medium": YELLOW, "low": GREEN}
    RISK_COLORS = {"Low Risk": GREEN, "Medium Risk": YELLOW, "High Risk": RED}

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", fontSize=22, textColor=ACCENT,
                         fontName="Helvetica-Bold", spaceAfter=4)
    h2 = ParagraphStyle("H2", fontSize=13, textColor=TEXT,
                         fontName="Helvetica-Bold", spaceAfter=4, spaceBefore=12)
    h3 = ParagraphStyle("H3", fontSize=11, textColor=ACCENT,
                         fontName="Helvetica-Bold", spaceAfter=4)
    body = ParagraphStyle("body", fontSize=9, textColor=TEXT,
                           fontName="Helvetica", leading=14)
    small = ParagraphStyle("small", fontSize=8, textColor=MUTED,
                            fontName="Helvetica", leading=12)
    mono = ParagraphStyle("mono", fontSize=8, textColor=GREEN,
                           fontName="Courier", leading=12)

    story = []

    # Header
    story.append(Paragraph("🛡  CyberShield SOC Platform", h1))
    story.append(Paragraph("Security Assessment Report", h2))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 8))

    # Metadata table
    risk_label = prediction["label"]
    risk_color = RISK_COLORS.get(risk_label, YELLOW)
    meta = [
        ["Target URL", url],
        ["Scan Timestamp", scan_ts],
        ["Risk Classification", risk_label],
        ["Confidence", f"{prediction['confidence']*100:.1f}%"],
        ["Analyst System", "CyberShield AI — XGBoost v3"],
    ]
    t = Table(meta, colWidths=[1.6*inch, 5.5*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PANEL),
        ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#111520")),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), TEXT),
        ("TEXTCOLOR", (1, 2), (1, 2), risk_color),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#161b27"), colors.HexColor("#111520")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#232a3b")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    # Probability breakdown
    story.append(Paragraph("Threat Detection Results", h2))
    prob_rows = [["Risk Category", "Probability"]]
    for lbl, prob in prediction["probabilities"].items():
        prob_rows.append([lbl, f"{prob*100:.2f}%"])
    pt = Table(prob_rows, colWidths=[3*inch, 2*inch])
    pt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PANEL),
        ("TEXTCOLOR", (0, 0), (-1, 0), ACCENT),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#232a3b")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("TEXTCOLOR", (0, 1), (-1, -1), TEXT),
    ]))
    story.append(pt)
    story.append(Spacer(1, 16))

    # SHAP explainability
    if shap_data and shap_data.get("top_features"):
        story.append(Paragraph("SHAP Explainability — Top Contributing Features", h2))
        shap_rows = [["Feature", "SHAP Value", "Direction"]]
        for feat_name, sv in shap_data["top_features"][:10]:
            direction = "↑ Increases Risk" if sv > 0 else "↓ Reduces Risk"
            shap_rows.append([feat_name, f"{sv:+.4f}", direction])
        st2 = Table(shap_rows, colWidths=[3*inch, 1.5*inch, 2.5*inch])
        st2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PANEL),
            ("TEXTCOLOR", (0, 0), (-1, 0), ACCENT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#232a3b")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(st2)
        story.append(Spacer(1, 16))

    # Vulnerability findings
    story.append(Paragraph("Vulnerability Findings", h2))
    counts = {k: 0 for k in ["critical", "high", "medium", "low"]}
    for v in vulns:
        counts[v["severity"]] = counts.get(v["severity"], 0) + 1

    sum_rows = [["Severity", "Count"]]
    for sev in ["critical", "high", "medium", "low"]:
        sum_rows.append([sev.upper(), str(counts[sev])])
    st3 = Table(sum_rows, colWidths=[2*inch, 1*inch])
    st3.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PANEL),
        ("TEXTCOLOR", (0, 0), (-1, 0), ACCENT),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#232a3b")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("TEXTCOLOR", (1, 1), (1, 1), RED),
        ("TEXTCOLOR", (1, 2), (1, 2), ORANGE),
        ("TEXTCOLOR", (1, 3), (1, 3), YELLOW),
        ("TEXTCOLOR", (1, 4), (1, 4), GREEN),
    ]))
    story.append(st3)
    story.append(Spacer(1, 10))

    for v in vulns:
        c = SEV_COLORS.get(v["severity"], TEXT)
        story.append(Paragraph(f"[{v['severity'].upper()}]  {v['title']}", h3))
        story.append(Paragraph(v["description"], body))
        story.append(Spacer(1, 6))

    # Remediation
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#232a3b")))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Remediation Recommendations", h2))
    recs = [
        "Enable HSTS with a minimum max-age of 31536000 seconds and includeSubDomains.",
        "Implement a strict Content Security Policy to prevent XSS and data injection.",
        "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
        "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing attacks.",
        "Configure a Referrer-Policy such as strict-origin-when-cross-origin.",
        "Ensure SSL/TLS certificate is valid, not self-signed, and renewed before expiry.",
        "Avoid exposing server version information in the Server response header.",
        "Validate and sanitize all query parameters to prevent injection attacks.",
        "Avoid open redirects; validate all redirect targets against an allowlist.",
        "Monitor domain age and flag newly registered domains in alerting pipelines.",
    ]
    for i, rec in enumerate(recs, 1):
        story.append(Paragraph(f"{i}. {rec}", body))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Report generated by CyberShield SOC Platform — AI-Powered Threat Intelligence", small))

    doc.build(story)
    buf.seek(0)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────
# CHART HELPERS
# ─────────────────────────────────────────────────────────────
CHART_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#8a95b0", family="Inter, sans-serif", size=11),
    margin=dict(l=10, r=10, t=30, b=10),
)


def risk_gauge(confidence, risk_class):
    colors_map = {0: "#22d89a", 1: "#fbbf24", 2: "#ef4444"}
    color = colors_map.get(risk_class, "#3d8ef0")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=round(confidence * 100, 1),
        number={"suffix": "%", "font": {"size": 28, "color": color}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#4f5a72",
                     "tickfont": {"size": 10}},
            "bar": {"color": color, "thickness": 0.3},
            "bgcolor": "#161b27",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 33],  "color": "rgba(34,216,154,0.08)"},
                {"range": [33, 66], "color": "rgba(251,191,36,0.08)"},
                {"range": [66, 100],"color": "rgba(239,68,68,0.08)"},
            ],
            "threshold": {"line": {"color": color, "width": 3},
                          "thickness": 0.8, "value": confidence*100},
        },
        title={"text": "Confidence Score", "font": {"size": 12, "color": "#8a95b0"}},
    ))
    fig.update_layout(**CHART_LAYOUT, height=200)
    return fig


def probability_bar(probabilities):
    labels = list(probabilities.keys())
    values = [v*100 for v in probabilities.values()]
    palette = ["#22d89a", "#fbbf24", "#ef4444"]
    fig = go.Figure(go.Bar(
        x=values, y=labels, orientation="h",
        marker_color=palette,
        marker_line_width=0,
        text=[f"{v:.1f}%" for v in values],
        textposition="outside",
        textfont=dict(color="#e4e8f0", size=11),
    ))
    fig.update_layout(**CHART_LAYOUT, height=160,
                      xaxis=dict(range=[0, 115], showgrid=False,
                                 showticklabels=False, zeroline=False),
                      yaxis=dict(showgrid=False, zeroline=False))
    return fig


def feature_importance_chart(model):
    imp = model.feature_importances_
    pairs = sorted(zip(FEATURE_NAMES, imp), key=lambda x: x[1], reverse=True)[:15]
    names = [p[0].replace("_", " ") for p in pairs]
    vals  = [p[1] for p in pairs]
    colors_list = [f"rgba(61,142,240,{0.4 + 0.6*v/max(vals)})" for v in vals]
    fig = go.Figure(go.Bar(
        x=vals[::-1], y=names[::-1], orientation="h",
        marker_color=colors_list[::-1],
        marker_line_width=0,
    ))
    fig.update_layout(**CHART_LAYOUT, height=400,
                      xaxis=dict(title="Importance", gridcolor="#1c2235", zeroline=False),
                      yaxis=dict(showgrid=False, zeroline=False),
                      title=dict(text="Top 15 Model Feature Importances",
                                 font=dict(size=13, color="#e4e8f0")))
    return fig


def trend_chart(assessments):
    if not assessments:
        return None
    df = pd.DataFrame(assessments)
    risk_counts = df.groupby(["timestamp", "risk_label"]).size().reset_index(name="count")
    fig = go.Figure()
    for lbl, color in [("Low Risk","#22d89a"),("Medium Risk","#fbbf24"),("High Risk","#ef4444")]:
        sub = risk_counts[risk_counts["risk_label"] == lbl]
        if not sub.empty:
            fig.add_trace(go.Scatter(
                x=sub["timestamp"], y=sub["count"],
                mode="lines+markers", name=lbl,
                line=dict(color=color, width=2),
                marker=dict(color=color, size=6),
            ))
    fig.update_layout(**CHART_LAYOUT, height=280,
                      xaxis=dict(gridcolor="#1c2235", zeroline=False),
                      yaxis=dict(gridcolor="#1c2235", zeroline=False, title="Assessments"),
                      legend=dict(bgcolor="rgba(0,0,0,0)"),
                      title=dict(text="Risk Trend Over Time",
                                 font=dict(size=13, color="#e4e8f0")))
    return fig


def vuln_heatmap(vulns):
    cats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        cats[v["severity"]] += 1
    labels = ["Critical", "High", "Medium", "Low"]
    values = [cats["critical"], cats["high"], cats["medium"], cats["low"]]
    palette = ["#ef4444", "#f97316", "#fbbf24", "#22d89a"]
    fig = go.Figure(go.Bar(
        x=labels, y=values,
        marker_color=palette,
        marker_line_width=0,
        text=values,
        textposition="outside",
        textfont=dict(color="#e4e8f0"),
    ))
    fig.update_layout(**CHART_LAYOUT, height=220,
                      xaxis=dict(showgrid=False, zeroline=False),
                      yaxis=dict(gridcolor="#1c2235", zeroline=False),
                      title=dict(text="Vulnerability Distribution",
                                 font=dict(size=13, color="#e4e8f0")))
    return fig


# ─────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────
def render_sidebar():
    with st.sidebar:
        st.markdown("""
        <div style="padding:1rem 0 1.5rem;">
            <div class="brand-logo">🛡 CyberShield</div>
            <div class="brand-sub">Security Operations Platform</div>
        </div>
        """, unsafe_allow_html=True)

        page = st.radio(
            "Navigation",
            ["Executive Overview", "URL Scanner", "Threat Detection",
             "SHAP Explainability", "Vulnerabilities", "Investigation Report",
             "Threat Intelligence"],
            label_visibility="collapsed",
        )

        st.markdown("---")

        # Model status
        if st.session_state["model_loaded"]:
            st.markdown("""
            <div class="status-live">
                <div class="status-dot"></div>
                Model Active
            </div>
            """, unsafe_allow_html=True)
            src = st.session_state.get("model_source", "")
            st.caption(src)
        else:
            st.warning("Model not loaded")
            if st.button("Load Model", key="load_model_btn"):
                with st.spinner("Loading model..."):
                    load_or_create_model()
                st.rerun()

        st.markdown("---")
        st.caption(f"**Assessments:** {len(st.session_state['assessments'])}")
        st.caption(f"**Session started:** {datetime.datetime.now().strftime('%H:%M UTC')}")

        if st.session_state["assessments"]:
            high_count = sum(1 for a in st.session_state["assessments"]
                             if a["risk_label"] == "High Risk")
            if high_count:
                st.error(f"⚠ {high_count} High-Risk finding(s) this session")

        return page


# ─────────────────────────────────────────────────────────────
# PAGE: EXECUTIVE OVERVIEW
# ─────────────────────────────────────────────────────────────
def page_overview():
    st.markdown('<div class="section-header"><div class="dot" style="background:#3d8ef0"></div>Executive Overview</div>', unsafe_allow_html=True)

    a = st.session_state["assessments"]
    total   = len(a)
    high    = sum(1 for x in a if x["risk_label"] == "High Risk")
    medium  = sum(1 for x in a if x["risk_label"] == "Medium Risk")
    low     = sum(1 for x in a if x["risk_label"] == "Low Risk")
    avg_conf = (sum(x["confidence"] for x in a) / total * 100) if total else 0

    st.markdown(f"""
    <div class="kpi-grid">
      <div class="kpi-card blue">
        <div class="kpi-label">Total Assessments</div>
        <div class="kpi-value">{total}</div>
        <div class="kpi-sub">This session</div>
      </div>
      <div class="kpi-card red">
        <div class="kpi-label">High Risk</div>
        <div class="kpi-value">{high}</div>
        <div class="kpi-sub">Requires immediate action</div>
      </div>
      <div class="kpi-card orange">
        <div class="kpi-label">Medium Risk</div>
        <div class="kpi-value">{medium}</div>
        <div class="kpi-sub">Review recommended</div>
      </div>
      <div class="kpi-card green">
        <div class="kpi-label">Low Risk</div>
        <div class="kpi-value">{low}</div>
        <div class="kpi-sub">Monitor periodically</div>
      </div>
      <div class="kpi-card purple">
        <div class="kpi-label">Avg Confidence</div>
        <div class="kpi-value">{avg_conf:.0f}%</div>
        <div class="kpi-sub">Model certainty</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([2, 1])
    with col1:
        if a:
            fig = trend_chart(a)
            if fig:
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.markdown("""
            <div class="panel" style="text-align:center;padding:3rem;color:var(--text-muted);">
                <div style="font-size:2rem">📡</div>
                <div style="margin-top:0.5rem;font-size:0.9rem">No assessments yet</div>
                <div style="font-size:0.78rem;margin-top:0.3rem">Run a URL scan to populate the dashboard</div>
            </div>
            """, unsafe_allow_html=True)

    with col2:
        if st.session_state["model_loaded"]:
            model = st.session_state["model"]
            st.plotly_chart(feature_importance_chart(model),
                            use_container_width=True,
                            config={"displayModeBar": False})

    # Recent assessments table
    if a:
        st.markdown('<div class="section-header"><div class="dot" style="background:#22d89a"></div>Recent Assessments</div>', unsafe_allow_html=True)
        df = pd.DataFrame(a)[["url", "timestamp", "risk_label", "confidence", "vuln_count"]]
        df["confidence"] = df["confidence"].apply(lambda x: f"{x*100:.1f}%")
        df.columns = ["URL", "Timestamp", "Risk", "Confidence", "Vulnerabilities"]
        st.dataframe(df.tail(20), use_container_width=True, hide_index=True)


# ─────────────────────────────────────────────────────────────
# PAGE: URL SCANNER
# ─────────────────────────────────────────────────────────────
def page_scanner():
    st.markdown('<div class="section-header"><div class="dot" style="background:#00d4ff"></div>URL Vulnerability Scanner</div>', unsafe_allow_html=True)

    if not st.session_state["model_loaded"]:
        with st.spinner("Initialising model..."):
            load_or_create_model()

    url = st.text_input(
        "Target URL",
        placeholder="https://example.com",
        key="scan_url_input",
        help="Enter a full URL including protocol (https:// or http://)",
    )

    col_btn, col_clear = st.columns([2, 5])
    with col_btn:
        scan_btn = st.button("🔍  Run Assessment", type="primary", use_container_width=True)
    with col_clear:
        if st.button("Clear Results", use_container_width=False):
            st.session_state["scan_result"] = None
            st.rerun()

    if scan_btn and url:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        st.session_state["_current_url"] = url
        _run_scan(url)

    if st.session_state["scan_result"]:
        _display_scan_summary(st.session_state["scan_result"])


def _run_scan(url: str):
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc.split(":")[0]
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    progress = st.progress(0)
    status   = st.empty()

    result = {"url": url, "timestamp": ts, "hostname": hostname}

    status.info("🔬 Extracting URL features…")
    progress.progress(10)
    feat = extract_url_features(url)

    status.info("🔐 Inspecting SSL certificate…")
    progress.progress(25)
    ssl_info = check_ssl(hostname, feat)
    result["ssl"] = ssl_info

    status.info("📡 Fetching HTTP headers…")
    progress.progress(45)
    header_info = check_headers(url, feat)
    result["headers"] = header_info

    status.info("🌐 WHOIS domain lookup…")
    progress.progress(65)
    whois_info = check_whois(hostname, feat)
    result["whois"] = whois_info

    status.info("🤖 Running XGBoost threat model…")
    progress.progress(80)
    model      = st.session_state["model"]
    prediction = predict(model, feat)
    result["prediction"] = prediction
    result["features"]   = feat

    status.info("🧠 Computing SHAP explanations…")
    progress.progress(90)
    sv, base_val = compute_shap(model, prediction["features"])
    shap_data = None
    if sv is not None:
        pred_class = prediction["class"]
        if isinstance(sv, np.ndarray) and sv.ndim == 3:
            vals = sv[pred_class][0]
        else:
            vals = sv[0]
        pairs = sorted(zip(FEATURE_NAMES, vals), key=lambda x: abs(x[1]), reverse=True)
        shap_data = {
            "values": vals,
            "top_features": pairs,
            "base_value": base_val[pred_class] if isinstance(base_val, (list, np.ndarray)) else base_val,
        }
    result["shap"] = shap_data

    status.info("🔎 Evaluating vulnerability rules…")
    progress.progress(97)
    vulns = evaluate_vulnerabilities(feat, header_info)
    result["vulnerabilities"] = vulns

    progress.progress(100)
    status.success(f"✅ Assessment complete — {len(vulns)} findings detected")
    time.sleep(0.5)
    progress.empty()
    status.empty()

    # Save to session history
    st.session_state["assessments"].append({
        "url":        url,
        "timestamp":  ts,
        "risk_label": prediction["label"],
        "confidence": prediction["confidence"],
        "vuln_count": len(vulns),
    })
    st.session_state["scan_result"] = result


def _display_scan_summary(result):
    pred   = result["prediction"]
    vulns  = result["vulnerabilities"]
    ssl    = result.get("ssl", {})
    whois_d = result.get("whois", {})
    headers = result.get("headers", {})
    feat   = result.get("features", {})

    risk_colors = {"Low Risk": "#22d89a", "Medium Risk": "#fbbf24", "High Risk": "#ef4444"}
    rc = risk_colors.get(pred["label"], "#3d8ef0")

    # Risk banner
    st.markdown(f"""
    <div class="panel" style="border-color:{rc};border-left:4px solid {rc};">
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
                <div style="font-size:0.72rem;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.08em;">Threat Classification</div>
                <div style="font-size:1.8rem;font-weight:700;color:{rc};font-family:'JetBrains Mono',monospace;">{pred["label"]}</div>
                <div style="font-size:0.82rem;color:var(--text-secondary);margin-top:0.3rem;">{result["url"]}</div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:0.72rem;color:var(--text-muted);">Confidence</div>
                <div style="font-size:2.4rem;font-weight:700;color:{rc};font-family:'JetBrains Mono',monospace;">{pred["confidence"]*100:.1f}%</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""<div class="panel">
        <div class="kpi-label">SSL Status</div>
        <div style="font-size:1.1rem;font-weight:600;color:{'#22d89a' if ssl.get('valid') else '#ef4444'}">
        {'✓ Valid' if ssl.get('valid') else '✗ Invalid'}</div>
        <div class="kpi-sub">{ssl.get('days_remaining', 0)} days remaining</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        age = whois_d.get("age_days", feat.get("domain_age_days", 0))
        st.markdown(f"""<div class="panel">
        <div class="kpi-label">Domain Age</div>
        <div style="font-size:1.1rem;font-weight:600;color:{'#ef4444' if age < 30 else '#22d89a'}">{age} days</div>
        <div class="kpi-sub">{'⚠ Newly registered' if age < 30 else 'Established domain'}</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        hdr_score = 5 - sum([feat.get(f"missing_{h}", 1) for h in ["hsts","csp","xframe","xcontent","referrer"]])
        st.markdown(f"""<div class="panel">
        <div class="kpi-label">Security Headers</div>
        <div style="font-size:1.1rem;font-weight:600;color:{'#22d89a' if hdr_score>=4 else '#fbbf24' if hdr_score>=2 else '#ef4444'}">{hdr_score}/5 Present</div>
        <div class="kpi-sub">HTTP security headers</div>
        </div>""", unsafe_allow_html=True)
    with col4:
        crit_h = sum(1 for v in vulns if v["severity"] in ["critical","high"])
        st.markdown(f"""<div class="panel">
        <div class="kpi-label">Critical/High Findings</div>
        <div style="font-size:1.1rem;font-weight:600;color:{'#ef4444' if crit_h else '#22d89a'}">{crit_h} Issues</div>
        <div class="kpi-sub">{len(vulns)} total findings</div>
        </div>""", unsafe_allow_html=True)

    # Tabs for details
    t1, t2, t3, t4 = st.tabs(["📋 Domain Info", "🔐 SSL Details", "📡 HTTP Headers", "🌐 WHOIS"])

    with t1:
        parsed = urllib.parse.urlparse(result["url"])
        info = {
            "Protocol": parsed.scheme.upper(),
            "Hostname": parsed.netloc,
            "Path": parsed.path or "/",
            "Query String": parsed.query or "—",
            "URL Length": len(result["url"]),
            "Subdomain Depth": feat.get("subdomain_depth", 0),
            "HTTPS": "Yes" if feat.get("has_https") else "No",
            "Suspicious TLD": "Yes ⚠" if feat.get("has_suspicious_tld") else "No",
            "IP in URL": "Yes ⚠" if feat.get("has_ip_address") else "No",
            "Phishing Keywords": feat.get("phishing_keywords", 0),
        }
        for k, v in info.items():
            st.markdown(f"**{k}:** `{v}`")

    with t2:
        if ssl.get("valid"):
            cert = ssl.get("cert", {})
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            st.success(f"Certificate valid — {ssl.get('days_remaining')} days until expiry")
            for k, v in [
                ("Common Name", subject.get("commonName", "—")),
                ("Issuer Organization", issuer.get("organizationName", "—")),
                ("Valid From", cert.get("notBefore", "—")),
                ("Valid Until", cert.get("notAfter", "—")),
                ("TLS Version", cert.get("version", "—")),
            ]:
                st.markdown(f"**{k}:** `{v}`")
        else:
            st.error(f"SSL check failed: {ssl.get('error', 'Unknown error')}")

    with t3:
        if "error" in headers:
            st.error(f"Header fetch failed: {headers['error']}")
        else:
            st.markdown(f"**Status:** `{headers.get('status_code', '—')}`")
            st.markdown(f"**Final URL:** `{headers.get('final_url', '—')}`")
            st.markdown(f"**Redirects:** `{headers.get('redirect_count', 0)}`")
            st.markdown(f"**Server:** `{headers.get('server', 'Unknown')}`")
            st.markdown("---")
            for hdr, key in [("HSTS","hsts"),("CSP","csp"),
                              ("X-Frame-Options","x_frame"),
                              ("X-Content-Type-Options","x_content"),
                              ("Referrer-Policy","referrer")]:
                val = headers.get(key, "MISSING")
                icon = "✓" if val != "MISSING" else "✗"
                color = "#22d89a" if val != "MISSING" else "#ef4444"
                st.markdown(f'<span style="color:{color}">{icon}</span> **{hdr}:** `{val}`',
                            unsafe_allow_html=True)

    with t4:
        if "error" in whois_d:
            st.warning(f"WHOIS lookup limited: {whois_d['error']}")
        for k, v in whois_d.items():
            if k != "error":
                val = v if not isinstance(v, list) else ", ".join(str(x) for x in v[:3])
                st.markdown(f"**{k.replace('_',' ').title()}:** `{val}`")


# ─────────────────────────────────────────────────────────────
# PAGE: THREAT DETECTION
# ─────────────────────────────────────────────────────────────
def page_threat():
    st.markdown('<div class="section-header"><div class="dot" style="background:#ef4444"></div>Threat Detection Engine</div>', unsafe_allow_html=True)

    if not st.session_state.get("scan_result"):
        st.info("Run a URL scan first (URL Scanner tab)")
        return

    result = st.session_state["scan_result"]
    pred   = result["prediction"]

    col1, col2 = st.columns([1, 1])
    with col1:
        fig = risk_gauge(pred["confidence"], pred["class"])
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with col2:
        fig2 = probability_bar(pred["probabilities"])
        st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})

    st.markdown('<div class="section-header"><div class="dot" style="background:#a855f7"></div>Feature Vector</div>', unsafe_allow_html=True)
    feat = result["features"]
    df_feat = pd.DataFrame([feat]).T.reset_index()
    df_feat.columns = ["Feature", "Value"]
    df_feat["Value"] = df_feat["Value"].apply(lambda x: round(float(x), 4) if isinstance(x, (int, float)) else x)

    # Color-code by risk signal
    def color_row(row):
        risk_features = ["missing_hsts","missing_csp","missing_xframe","missing_xcontent",
                         "has_suspicious_tld","has_ip_address","is_new_domain","has_open_redirect"]
        if row["Feature"] in risk_features and row["Value"] == 1:
            return ["color: #ef4444"] * 2
        if row["Feature"] in ["ssl_valid","has_https"] and row["Value"] == 0:
            return ["color: #ef4444"] * 2
        return [""] * 2

    st.dataframe(df_feat.style.apply(color_row, axis=1),
                 use_container_width=True, hide_index=True, height=350)

    st.markdown(f"""
    <div style="background:rgba(61,142,240,0.08);border:1px solid rgba(61,142,240,0.2);
                border-radius:8px;padding:1rem;margin-top:1rem;font-size:0.82rem;color:var(--text-secondary);">
        <strong style="color:var(--accent-blue)">Model Info</strong><br>
        {st.session_state.get('model_source', 'XGBoost Classifier')} &nbsp;|&nbsp;
        {len(FEATURE_NAMES)} features &nbsp;|&nbsp; 3-class classification
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# PAGE: SHAP EXPLAINABILITY
# ─────────────────────────────────────────────────────────────
def page_shap():
    st.markdown('<div class="section-header"><div class="dot" style="background:#a855f7"></div>SHAP Explainability</div>', unsafe_allow_html=True)

    if not st.session_state.get("scan_result"):
        st.info("Run a URL scan first (URL Scanner tab)")
        return

    result    = st.session_state["scan_result"]
    shap_data = result.get("shap")
    pred      = result["prediction"]

    if not shap_data:
        st.warning("SHAP computation not available for this scan.")
        return

    top = shap_data["top_features"]
    max_abs = max(abs(v) for _, v in top) if top else 1

    st.markdown(f"""
    <div class="panel">
        <div style="font-size:0.78rem;color:var(--text-secondary);margin-bottom:0.8rem;">
            Feature contributions toward → <strong style="color:var(--text-primary)">{pred['label']}</strong>
            &nbsp;|&nbsp; Base value: <code>{shap_data['base_value']:.4f}</code>
        </div>
    """, unsafe_allow_html=True)

    for feat_name, sv in top[:15]:
        pct = abs(sv) / max_abs * 100
        bar_cls = "shap-bar-pos" if sv > 0 else "shap-bar-neg"
        val_cls = "pos" if sv > 0 else "neg"
        arrow = "↑" if sv > 0 else "↓"
        st.markdown(f"""
        <div class="shap-row">
            <div class="shap-label">{feat_name.replace('_',' ')}</div>
            <div class="shap-bar-wrap">
                <div class="{bar_cls}" style="width:{pct:.1f}%"></div>
            </div>
            <div class="shap-val {val_cls}">{arrow} {abs(sv):.4f}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

    # Waterfall-style chart
    top10  = top[:10]
    labels = [f[0].replace("_", " ") for f in top10]
    vals   = [f[1] for f in top10]
    colors = ["#ef4444" if v > 0 else "#22d89a" for v in vals]

    fig = go.Figure(go.Bar(
        x=labels, y=vals,
        marker_color=colors,
        marker_line_width=0,
        text=[f"{v:+.4f}" for v in vals],
        textposition="outside",
        textfont=dict(color="#e4e8f0", size=10),
    ))
    fig.add_hline(y=0, line_color="#4f5a72", line_width=1)
    fig.update_layout(**CHART_LAYOUT, height=320,
                      xaxis=dict(showgrid=False, zeroline=False,
                                 tickfont=dict(size=10)),
                      yaxis=dict(gridcolor="#1c2235", zeroline=False,
                                 title="SHAP Value"),
                      title=dict(text="SHAP Waterfall — Top 10 Features",
                                 font=dict(size=13, color="#e4e8f0")))
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    # Analyst interpretation
    st.markdown('<div class="section-header"><div class="dot" style="background:#fbbf24"></div>Analyst Interpretation</div>', unsafe_allow_html=True)
    risk_feats = [(n, v) for n, v in top if v > 0]
    safe_feats = [(n, v) for n, v in top if v < 0]

    if risk_feats:
        st.markdown('<div class="alert-high">', unsafe_allow_html=True)
        st.markdown("**🔴 Risk-Increasing Signals**")
        for n, v in risk_feats[:5]:
            st.markdown(f"- `{n.replace('_',' ')}` → **+{v:.4f}** risk contribution")
        st.markdown("</div>", unsafe_allow_html=True)

    if safe_feats:
        st.markdown('<div class="alert-low">', unsafe_allow_html=True)
        st.markdown("**🟢 Risk-Reducing Signals**")
        for n, v in safe_feats[:5]:
            st.markdown(f"- `{n.replace('_',' ')}` → **{v:.4f}** (mitigating factor)")
        st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# PAGE: VULNERABILITIES
# ─────────────────────────────────────────────────────────────
def page_vulns():
    st.markdown('<div class="section-header"><div class="dot" style="background:#f97316"></div>Vulnerability Findings</div>', unsafe_allow_html=True)

    if not st.session_state.get("scan_result"):
        st.info("Run a URL scan first (URL Scanner tab)")
        return

    vulns = st.session_state["scan_result"]["vulnerabilities"]
    if not vulns:
        st.success("No vulnerabilities detected.")
        return

    st.plotly_chart(vuln_heatmap(vulns), use_container_width=True,
                    config={"displayModeBar": False})

    for sev, color, icon in [
        ("critical", "#ef4444", "🔴"),
        ("high",     "#f97316", "🟠"),
        ("medium",   "#fbbf24", "🟡"),
        ("low",      "#22d89a", "🟢"),
    ]:
        group = [v for v in vulns if v["severity"] == sev]
        if not group:
            continue
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:0.6rem;margin:1.2rem 0 0.6rem;">
            <span>{icon}</span>
            <span style="font-size:0.78rem;font-weight:600;text-transform:uppercase;
                         letter-spacing:0.1em;color:{color};">{sev} ({len(group)})</span>
        </div>
        """, unsafe_allow_html=True)
        for v in group:
            st.markdown(f"""
            <div class="finding-row">
                <div>
                    <div class="finding-title">{v['title']}</div>
                    <div class="finding-desc">{v['description']}</div>
                </div>
                <div class="badge badge-{sev}">{sev}</div>
            </div>
            """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# PAGE: INVESTIGATION REPORT
# ─────────────────────────────────────────────────────────────
def page_report():
    st.markdown('<div class="section-header"><div class="dot" style="background:#22d89a"></div>Analyst Investigation Report</div>', unsafe_allow_html=True)

    if not st.session_state.get("scan_result"):
        st.info("Run a URL scan first (URL Scanner tab)")
        return

    result = st.session_state["scan_result"]
    pred   = result["prediction"]
    vulns  = result["vulnerabilities"]
    shap_d = result.get("shap")

    # Inline report preview
    risk_colors = {"Low Risk": "#22d89a", "Medium Risk": "#fbbf24", "High Risk": "#ef4444"}
    rc = risk_colors.get(pred["label"], "#3d8ef0")

    st.markdown(f"""
    <div class="panel">
        <div style="border-bottom:1px solid var(--border);padding-bottom:1rem;margin-bottom:1rem;">
            <div style="font-size:1.2rem;font-weight:700;color:var(--text-primary);">
                🛡 CyberShield SOC — Security Assessment Report
            </div>
            <div style="font-size:0.78rem;color:var(--text-muted);margin-top:0.3rem;">
                Generated {result['timestamp']}
            </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
            <div>
                <div class="kpi-label">Target</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.82rem;
                            color:var(--text-primary);word-break:break-all;">{result['url']}</div>
            </div>
            <div>
                <div class="kpi-label">Risk Classification</div>
                <div style="font-size:1.1rem;font-weight:700;color:{rc};">{pred['label']}</div>
            </div>
            <div>
                <div class="kpi-label">Model Confidence</div>
                <div style="font-size:1.1rem;font-weight:600;color:var(--accent-blue);">
                    {pred['confidence']*100:.1f}%
                </div>
            </div>
            <div>
                <div class="kpi-label">Findings</div>
                <div style="font-size:1.1rem;font-weight:600;color:var(--text-primary);">
                    {len(vulns)} vulnerabilities
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if shap_d:
        st.markdown('<div class="section-header"><div class="dot" style="background:#a855f7"></div>Key Risk Drivers</div>', unsafe_allow_html=True)
        for n, v in shap_d["top_features"][:5]:
            arrow = "↑ increases" if v > 0 else "↓ reduces"
            color = "#ef4444" if v > 0 else "#22d89a"
            st.markdown(f'<span style="color:{color}">●</span> **{n.replace("_"," ")}** — {arrow} risk score by `{abs(v):.4f}`', unsafe_allow_html=True)

    st.markdown('<div class="section-header"><div class="dot" style="background:#f97316"></div>Vulnerabilities</div>', unsafe_allow_html=True)
    for v in vulns[:10]:
        badge_cls = f"badge-{v['severity']}"
        st.markdown(f"""
        <div style="display:flex;gap:0.8rem;align-items:flex-start;
                    padding:0.6rem 0;border-bottom:1px solid var(--border);">
            <span class="badge {badge_cls}">{v['severity']}</span>
            <div>
                <div style="font-size:0.88rem;font-weight:500;">{v['title']}</div>
                <div style="font-size:0.78rem;color:var(--text-secondary);">{v['description']}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="section-header"><div class="dot" style="background:#22d89a"></div>Remediation</div>', unsafe_allow_html=True)
    recs = [
        "Deploy HSTS with `max-age=31536000; includeSubDomains; preload`.",
        "Implement Content Security Policy to restrict resource origins.",
        "Enforce X-Frame-Options: DENY to block clickjacking vectors.",
        "Renew or obtain a trusted SSL/TLS certificate immediately if invalid.",
        "Validate all query parameters against allow-listed patterns.",
        "Register domain auto-renew and enable WHOIS privacy.",
    ]
    for i, r in enumerate(recs, 1):
        st.markdown(f"**{i}.** {r}")

    # PDF download
    st.markdown("---")
    if st.button("📄  Generate & Download PDF Report", type="primary"):
        with st.spinner("Rendering PDF…"):
            pdf_bytes = generate_pdf_report(
                result["url"], result["timestamp"],
                result["features"], pred, vulns, shap_d
            )
        st.download_button(
            label="⬇  Download Report PDF",
            data=pdf_bytes,
            file_name=f"soc_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf",
        )


# ─────────────────────────────────────────────────────────────
# PAGE: THREAT INTELLIGENCE
# ─────────────────────────────────────────────────────────────
def page_intel():
    st.markdown('<div class="section-header"><div class="dot" style="background:#fbbf24"></div>Threat Intelligence</div>', unsafe_allow_html=True)

    a = st.session_state["assessments"]

    col1, col2, col3 = st.columns(3)
    with col1:
        total = len(a)
        st.metric("Total Assessments", total)
    with col2:
        high = sum(1 for x in a if x["risk_label"] == "High Risk")
        st.metric("High-Risk URLs", high, delta=f"{high/total*100:.0f}%" if total else "0%")
    with col3:
        avg_vuln = sum(x["vuln_count"] for x in a) / total if total else 0
        st.metric("Avg Vulnerabilities/Scan", f"{avg_vuln:.1f}")

    if not a:
        st.markdown("""
        <div class="panel" style="text-align:center;padding:3rem;color:var(--text-muted);">
            <div style="font-size:2rem">📊</div>
            <div>No intelligence data yet — run assessments to populate</div>
        </div>
        """, unsafe_allow_html=True)
        return

    # Risk distribution pie
    col_a, col_b = st.columns(2)
    with col_a:
        risk_counts = {"Low Risk": 0, "Medium Risk": 0, "High Risk": 0}
        for x in a:
            risk_counts[x["risk_label"]] = risk_counts.get(x["risk_label"], 0) + 1
        fig = go.Figure(go.Pie(
            labels=list(risk_counts.keys()),
            values=list(risk_counts.values()),
            marker_colors=["#22d89a", "#fbbf24", "#ef4444"],
            hole=0.55,
            textinfo="label+percent",
            textfont=dict(color="#e4e8f0"),
        ))
        fig.update_layout(**CHART_LAYOUT, height=260,
                          title=dict(text="Risk Distribution",
                                     font=dict(size=13, color="#e4e8f0")),
                          showlegend=False)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with col_b:
        # Confidence distribution
        confs = [x["confidence"]*100 for x in a]
        fig2 = go.Figure(go.Histogram(
            x=confs,
            nbinsx=10,
            marker_color="#3d8ef0",
            marker_line_color="#1c2235",
            marker_line_width=1,
        ))
        fig2.update_layout(**CHART_LAYOUT, height=260,
                           xaxis=dict(title="Confidence %", gridcolor="#1c2235"),
                           yaxis=dict(title="Count", gridcolor="#1c2235"),
                           title=dict(text="Model Confidence Distribution",
                                      font=dict(size=13, color="#e4e8f0")))
        st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})

    # Trend
    if len(a) > 1:
        fig3 = trend_chart(a)
        if fig3:
            st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar": False})

    # Vulnerability frequency (aggregate)
    if st.session_state.get("scan_result"):
        vulns = st.session_state["scan_result"]["vulnerabilities"]
        if vulns:
            st.markdown('<div class="section-header"><div class="dot" style="background:#ef4444"></div>Latest Scan — Vulnerability Breakdown</div>', unsafe_allow_html=True)
            st.plotly_chart(vuln_heatmap(vulns), use_container_width=True,
                            config={"displayModeBar": False})

    # Attack pattern table
    st.markdown('<div class="section-header"><div class="dot" style="background:#3d8ef0"></div>Common Attack Patterns (Knowledge Base)</div>', unsafe_allow_html=True)
    patterns = pd.DataFrame([
        {"Pattern": "Missing HSTS", "Category": "Transport Security", "CVSS": "5.3", "Frequency": "High"},
        {"Pattern": "No CSP Header", "Category": "Injection Prevention", "CVSS": "6.1", "Frequency": "High"},
        {"Pattern": "Open Redirect", "Category": "URL Manipulation", "CVSS": "6.1", "Frequency": "Medium"},
        {"Pattern": "New Domain (< 30d)", "Category": "Phishing Indicator", "CVSS": "7.4", "Frequency": "Medium"},
        {"Pattern": "IP in URL", "Category": "Phishing / C2", "CVSS": "8.2", "Frequency": "Low"},
        {"Pattern": "Suspicious TLD", "Category": "Domain Risk", "CVSS": "6.5", "Frequency": "Medium"},
        {"Pattern": "Invalid SSL Cert", "Category": "Crypto/Transport", "CVSS": "7.4", "Frequency": "Medium"},
        {"Pattern": "Phishing Keywords", "Category": "Social Engineering", "CVSS": "7.5", "Frequency": "High"},
    ])
    st.dataframe(patterns, use_container_width=True, hide_index=True)


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def main():
    # Auto-load model on first run
    if not st.session_state["model_loaded"]:
        load_or_create_model()

    page = render_sidebar()

    if page == "Executive Overview":
        page_overview()
    elif page == "URL Scanner":
        page_scanner()
    elif page == "Threat Detection":
        page_threat()
    elif page == "SHAP Explainability":
        page_shap()
    elif page == "Vulnerabilities":
        page_vulns()
    elif page == "Investigation Report":
        page_report()
    elif page == "Threat Intelligence":
        page_intel()


if __name__ == "__main__":
    main()