
"""
soc_dashboard.py
================

CyberShield SOC Platform

Modules:
- URL Scanner using url_xgboost_model.pkl only
- Authentication Monitoring using rule-based authentication_monitor.py only
- SHAP Explainability for URL model predictions
- Vulnerability Assessment using rules
- Investigation Report
- Threat Intelligence Dashboard
"""
from __future__ import annotations

import os
import joblib
import pandas as pd
import plotly.express as px

from authentication_predict import predict_authentication


import datetime as dt
import hashlib
import math
import re
import socket
import ssl
import time
import urllib.parse
import warnings
from io import BytesIO
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st
from xgboost import XGBClassifier




try:
    import whois
except ImportError:
    whois = None

warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
AUTH_MODEL_PATH = APP_DIR / "C:\\Users\\Administrator\\OneDrive\\Documents\\3rd sem\\project Lab\\AI-Powered-Security-Operations-Platform-for-Threat-Detection-Alert-Triage-and-Incident-Investigation\\models\\authentication_xgboost_model.pkl"

AUTH_FEATURES_PATH = APP_DIR / "C:\\Users\\Administrator\\OneDrive\\Documents\\3rd sem\\project Lab\\AI-Powered-Security-Operations-Platform-for-Threat-Detection-Alert-Triage-and-Incident-Investigation\\models\\authentication_feature_names.pkl"

AUTH_ENCODER_PATH = APP_DIR / "C:\\Users\\Administrator\\OneDrive\\Documents\\3rd sem\\project Lab\\AI-Powered-Security-Operations-Platform-for-Threat-Detection-Alert-Triage-and-Incident-Investigation\\models\\authentication_label_encoder.pkl"

AUTH_ALERT_FILE = APP_DIR / "C:\\Users\\Administrator\\OneDrive\\Documents\\3rd sem\\project Lab\\AI-Powered-Security-Operations-Platform-for-Threat-Detection-Alert-Triage-and-Incident-Investigation\\outputs\\windows_event_alerts.csv"

URL_MODEL_PATH = APP_DIR / "C:\\Users\\Administrator\\OneDrive\\Documents\\3rd sem\\project Lab\\AI-Powered-Security-Operations-Platform-for-Threat-Detection-Alert-Triage-and-Incident-Investigation\\url_xgboost_model.pkl"
URL_LABEL_ENCODER_PATH = APP_DIR / "C:\\Users\\Administrator\\OneDrive\\Documents\\3rd sem\\project Lab\\AI-Powered-Security-Operations-Platform-for-Threat-Detection-Alert-Triage-and-Incident-Investigation\\url_label_encoder.pkl"
URL_FEATURE_NAMES = [
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

RISK_LABELS = ["Low Risk", "Medium Risk", "High Risk"]
RISK_COLORS = {
    "Low Risk": "#22c55e",
    "Medium Risk": "#f59e0b",
    "High Risk": "#ef4444",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc",
    ".top", ".club", ".work", ".party", ".date", ".faith",
    ".review", ".stream", ".download", ".link", ".click",
    ".zip", ".mov", ".cam",
}

PHISHING_KEYWORDS = [
    "login", "signin", "account", "update", "verify", "secure",
    "bank", "paypal", "ebay", "amazon", "netflix", "apple",
    "password", "confirm", "suspend", "unlock", "recover",
    "wallet", "crypto", "urgent", "limited", "free", "prize",
    "office365", "microsoft", "outlook", "onedrive", "dropbox",
    "invoice", "payment", "gift", "bonus",
]

SUSPICIOUS_PATTERNS = [
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"--[a-z]",
    r"[a-z]@[a-z]",
    r"paypal.*\.(?!com)",
    r"(?:secure|login|account).*-[a-z]+\.",
]


class URLModelError(RuntimeError):
    """Raised when the URL model cannot be loaded or validated."""


def configure_page() -> None:
    st.set_page_config(
        page_title="CyberShield SOC Platform",
        page_icon="Shield",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(
        """
        <style>
        .block-container { max-width: 1400px; padding-top: 1.25rem; }
        .metric-card {
            border: 1px solid #273244;
            border-radius: 8px;
            padding: 1rem;
            background: #111827;
        }
        .section-title {
            font-size: .8rem;
            font-weight: 700;
            letter-spacing: .08em;
            text-transform: uppercase;
            color: #94a3b8;
            border-bottom: 1px solid #273244;
            padding-bottom: .5rem;
            margin: 1rem 0;
        }
        .finding {
            border-left: 4px solid #64748b;
            padding: .75rem 1rem;
            margin: .5rem 0;
            background: #111827;
            border-radius: 6px;
        }
        .critical { border-left-color: #dc2626; }
        .high { border-left-color: #ef4444; }
        .medium { border-left-color: #f59e0b; }
        .low { border-left-color: #22c55e; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def init_session_state() -> None:
    defaults = {
        "url_model": None,
        "url_model_loaded": False,
        "url_model_source": "",
        "scan_result": None,
        "assessments": [],
        
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def get_model_feature_names(model: Any) -> list[str]:
    names = getattr(model, "feature_names_in_", None)

    if names is None and hasattr(model, "get_booster"):
        names = model.get_booster().feature_names

    if names is None:
        return []

    return [str(name) for name in list(names)]


def validate_url_model_features(model: Any) -> None:
    loaded_features = get_model_feature_names(model)

    missing_features = [
        feature for feature in URL_FEATURE_NAMES if feature not in loaded_features
    ]
    extra_features = [
        feature for feature in loaded_features if feature not in URL_FEATURE_NAMES
    ]

    if loaded_features != URL_FEATURE_NAMES:
        raise URLModelError(
            "URL model feature mismatch.\n\n"
            f"Expected features:\n{URL_FEATURE_NAMES}\n\n"
            f"Loaded features:\n{loaded_features}\n\n"
            f"Missing features:\n{missing_features}\n\n"
            f"Extra features:\n{extra_features}"
        )

def load_url_model():
    if not URL_MODEL_PATH.exists():
        st.error(f"URL model not found:\n{URL_MODEL_PATH}")
        st.stop()

    if not URL_LABEL_ENCODER_PATH.exists():
        st.error(f"Label encoder not found:\n{URL_LABEL_ENCODER_PATH}")
        st.stop()

    model = joblib.load(URL_MODEL_PATH)
    encoder = joblib.load(URL_LABEL_ENCODER_PATH)

    return model, encoder

def ensure_url_model():

    if "url_model_loaded" not in st.session_state:
        st.session_state["url_model_loaded"] = False

    if not st.session_state["url_model_loaded"]:

        model, encoder = load_url_model()

        st.session_state["url_model"] = model
        st.session_state["url_label_encoder"] = encoder
        st.session_state["url_model_loaded"] = True


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    frequencies = {char: value.count(char) / len(value) for char in set(value)}
    return -sum(prob * math.log2(prob) for prob in frequencies.values() if prob > 0)


def extract_url_features(url: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment
    host_without_port = domain.split(":")[0]

    features: dict[str, Any] = {
        "url_length": len(url),
        "domain_length": len(domain),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_digits": sum(char.isdigit() for char in url),
        "num_special_chars": sum(char in "@#!%&*=<>|" for char in url),
        "has_https": int(parsed.scheme == "https"),
        "has_ip_address": int(
            re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host_without_port) is not None
        ),
        "has_at_symbol": int("@" in url),
        "has_double_slash": int("//" in path),
        "has_suspicious_tld": int(any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)),
        "subdomain_depth": max(0, len(host_without_port.split(".")) - 2),
        "path_depth": len([part for part in path.split("/") if part]),
        "has_port": int(":" in domain),
        "has_query_params": int(bool(query)),
        "num_query_params": len(urllib.parse.parse_qs(query)),
        "has_fragment": int(bool(fragment)),
        "url_entropy": shannon_entropy(url),
        "ssl_valid": 0,
        "ssl_days_remaining": 0,
        "domain_age_days": 365,
        "is_new_domain": 0,
        "missing_hsts": 1,
        "missing_csp": 1,
        "missing_xframe": 1,
        "missing_xcontent": 1,
        "missing_referrer": 1,
        "has_open_redirect": int(
            re.search(r"(redirect|url|return|next|goto)=http", url, re.I) is not None
        ),
        "phishing_keywords": sum(keyword in url.lower() for keyword in PHISHING_KEYWORDS),
        "suspicious_pattern_score": sum(
            1 for pattern in SUSPICIOUS_PATTERNS if re.search(pattern, url, re.I)
        )
        / len(SUSPICIOUS_PATTERNS),
        "redirect_count": 0,
    }

    threat_tags = []
    if features["has_ip_address"]:
        threat_tags.append("IP address in URL")
    if features["has_open_redirect"]:
        threat_tags.append("Open redirect indicator")
    if features["has_suspicious_tld"]:
        threat_tags.append("Suspicious TLD")
    if features["phishing_keywords"] >= 2:
        threat_tags.append("Phishing keywords")

    features["_url"] = url
    features["_url_hash"] = hashlib.md5(url.encode("utf-8")).hexdigest()
    features["_timestamp"] = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    features["_threat_tags"] = threat_tags

    return features


def check_ssl(hostname: str, features: dict[str, Any]) -> dict[str, Any]:
    if not hostname:
        return {"valid": False, "error": "Missing hostname"}

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                expires_raw = cert.get("notAfter", "")
                expires = dt.datetime.strptime(expires_raw, "%b %d %H:%M:%S %Y %Z")
                days_remaining = max(0, (expires - dt.datetime.utcnow()).days)

                features["ssl_valid"] = 1
                features["ssl_days_remaining"] = days_remaining

                return {
                    "valid": True,
                    "days_remaining": days_remaining,
                    "not_before": cert.get("notBefore", "Unknown"),
                    "not_after": cert.get("notAfter", "Unknown"),
                    "issuer": cert.get("issuer", "Unknown"),
                }
    except Exception as exc:
        features["ssl_valid"] = 0
        features["ssl_days_remaining"] = 0
        return {"valid": False, "days_remaining": 0, "error": str(exc)}


def check_headers(url: str, features: dict[str, Any]) -> dict[str, Any]:
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "CyberShield-SOC/1.0"},
        )
        headers = {key.lower(): value for key, value in response.headers.items()}

        features["missing_hsts"] = int("strict-transport-security" not in headers)
        features["missing_csp"] = int("content-security-policy" not in headers)
        features["missing_xframe"] = int("x-frame-options" not in headers)
        features["missing_xcontent"] = int("x-content-type-options" not in headers)
        features["missing_referrer"] = int("referrer-policy" not in headers)
        features["redirect_count"] = len(response.history)

        return {
            "status_code": response.status_code,
            "final_url": response.url,
            "redirect_count": len(response.history),
            "hsts": headers.get("strict-transport-security", "Missing"),
            "csp": headers.get("content-security-policy", "Missing"),
            "x_frame": headers.get("x-frame-options", "Missing"),
            "x_content": headers.get("x-content-type-options", "Missing"),
            "referrer": headers.get("referrer-policy", "Missing"),
            "server": headers.get("server", "Unknown"),
        }
    except Exception as exc:
        return {"error": str(exc)}


def check_whois(hostname: str, features: dict[str, Any]) -> dict[str, Any]:
    if whois is None:
        return {"error": "python-whois is not installed", "age_days": features["domain_age_days"]}

    try:
        record = whois.whois(hostname)
        created = record.creation_date
        expires = record.expiration_date

        if isinstance(created, list):
            created = created[0]
        if isinstance(expires, list):
            expires = expires[0]

        if created:
            age_days = max(0, (dt.datetime.now() - created).days)
            features["domain_age_days"] = age_days
            features["is_new_domain"] = int(age_days < 30)

        return {
            "registrar": getattr(record, "registrar", "Unknown"),
            "created": str(created)[:10] if created else "Unknown",
            "expires": str(expires)[:10] if expires else "Unknown",
            "country": getattr(record, "country", "Unknown"),
            "age_days": features["domain_age_days"],
        }
    except Exception as exc:
        return {"error": str(exc), "age_days": features["domain_age_days"]}


def model_frame(features: dict[str, Any]) -> pd.DataFrame:
    frame = pd.DataFrame([{name: features[name] for name in URL_FEATURE_NAMES}])
    return frame[URL_FEATURE_NAMES]


def predict_url(model: XGBClassifier, features: dict[str, Any]) -> dict[str, Any]:
    print("=" * 60)
    print("URL_FEATURE_NAMES")
    print(URL_FEATURE_NAMES)
    print("Count:", len(URL_FEATURE_NAMES))

    frame = model_frame(features)

    probabilities = model.predict_proba(frame)[0]
    predicted_class = int(np.argmax(probabilities))

    encoder = st.session_state["url_label_encoder"]

    predicted_label = encoder.inverse_transform([predicted_class])[0]

    probability_dict = {
        encoder.inverse_transform([i])[0]: float(probabilities[i])
        for i in range(len(probabilities))
    }

    return {
        "class": predicted_class,
        "label": predicted_label,
        "confidence": float(probabilities[predicted_class]),
        "probabilities": probability_dict,
        "features_df": frame,
    }

def compute_shap_url(model: XGBClassifier, features_df: pd.DataFrame, predicted_class: int) -> dict[str, Any] | None:
    try:
        import shap

        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(features_df)
        values = np.asarray(shap_values)

        if values.ndim == 3:
            values = values.transpose(2, 0, 1)[predicted_class][0]
        elif values.ndim == 2:
            values = values[0]
        else:
            return None

        expected_value = explainer.expected_value
        if isinstance(expected_value, (list, np.ndarray)):
            base_value = float(expected_value[predicted_class])
        else:
            base_value = float(expected_value)

        top_features = sorted(
            zip(URL_FEATURE_NAMES, values),
            key=lambda item: abs(item[1]),
            reverse=True,
        )

        return {
            "top_features": [(name, float(value)) for name, value in top_features],
            "base_value": base_value,
        }
    except Exception as exc:
        return {"error": str(exc), "top_features": [], "base_value": 0.0}


VULN_RULES = [
    ("critical", "IP address in URL", "Raw IP usage is common in phishing and command infrastructure.", lambda f, h: f["has_ip_address"] == 1),
    ("critical", "Open redirect indicator", "URL contains redirect-style parameters pointing to HTTP destinations.", lambda f, h: f["has_open_redirect"] == 1),
    ("high", "Invalid or missing SSL", "Certificate validation failed or HTTPS is unavailable.", lambda f, h: f["ssl_valid"] == 0),
    ("high", "Suspicious TLD", "The domain uses a TLD frequently associated with abuse.", lambda f, h: f["has_suspicious_tld"] == 1),
    ("high", "Newly registered domain", "Domain age is below 30 days.", lambda f, h: f["is_new_domain"] == 1),
    ("high", "Missing HSTS", "Server does not enforce strict HTTPS transport.", lambda f, h: f["missing_hsts"] == 1),
    ("medium", "Missing Content Security Policy", "No CSP header was detected.", lambda f, h: f["missing_csp"] == 1),
    ("medium", "Missing X-Frame-Options", "Clickjacking protection header is missing.", lambda f, h: f["missing_xframe"] == 1),
    ("medium", "Missing X-Content-Type-Options", "MIME-sniffing protection header is missing.", lambda f, h: f["missing_xcontent"] == 1),
    ("medium", "Missing Referrer-Policy", "Referrer leakage control header is missing.", lambda f, h: f["missing_referrer"] == 1),
    ("medium", "Phishing keywords", "URL contains multiple credential or urgency keywords.", lambda f, h: f["phishing_keywords"] >= 2),
    ("medium", "Excessive redirects", "Multiple redirects may obscure the final destination.", lambda f, h: f["redirect_count"] > 2),
    ("low", "No HTTPS", "URL does not use HTTPS.", lambda f, h: f["has_https"] == 0),
    ("low", "High URL entropy", "URL appears unusually random or encoded.", lambda f, h: f["url_entropy"] > 4.5),
    ("low", "Suspicious structural pattern", "URL matches suspicious structural patterns.", lambda f, h: f["suspicious_pattern_score"] > 0),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def evaluate_vulnerabilities(features: dict[str, Any], headers: dict[str, Any]) -> list[dict[str, str]]:
    findings = []

    for severity, title, description, rule in VULN_RULES:
        try:
            if rule(features, headers):
                findings.append({
                    "severity": severity,
                    "title": title,
                    "description": description,
                })
        except Exception:
            continue

    return sorted(findings, key=lambda item: SEVERITY_ORDER[item["severity"]])


def run_scan(url: str) -> None:
    ensure_url_model()

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc.split(":")[0]
    timestamp = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    progress = st.progress(0)
    status = st.empty()

    try:
        status.info("Extracting URL features")
        progress.progress(15)
        features = extract_url_features(url)

        status.info("Checking SSL certificate")
        progress.progress(30)
        ssl_result = check_ssl(hostname, features)

        status.info("Checking HTTP security headers")
        progress.progress(50)
        headers_result = check_headers(url, features)

        status.info("Checking domain registration")
        progress.progress(65)
        whois_result = check_whois(hostname, features)

        status.info("Running URL XGBoost model")
        progress.progress(80)
        prediction = predict_url(st.session_state["url_model"], features)

        status.info("Computing SHAP explanation")
        progress.progress(90)
        shap_result = compute_shap_url(
            st.session_state["url_model"],
            prediction["features_df"],
            prediction["class"],
        )

        status.info("Evaluating vulnerability rules")
        progress.progress(97)
        vulnerabilities = evaluate_vulnerabilities(features, headers_result)

        result = {
            "url": url,
            "hostname": hostname,
            "timestamp": timestamp,
            "features": features,
            "ssl": ssl_result,
            "headers": headers_result,
            "whois": whois_result,
            "prediction": prediction,
            "shap": shap_result,
            "vulnerabilities": vulnerabilities,
        }

        st.session_state["scan_result"] = result
        st.session_state["assessments"].append({
            "url": url,
            "timestamp": timestamp,
            "risk_label": prediction["label"],
            "confidence": prediction["confidence"],
            "vuln_count": len(vulnerabilities),
        })

        progress.progress(100)
        status.success("Scan complete")
        time.sleep(0.3)

    except Exception as exc:
        status.error(f"Scan failed: {exc}")
        st.exception(exc)
    finally:
        progress.empty()

@st.cache_data(ttl=5)
def load_authentication_alerts():

    if not AUTH_ALERT_FILE.exists():

        return pd.DataFrame()

    try:

        df = pd.read_csv(AUTH_ALERT_FILE)

        if "Timestamp" in df.columns:

            df["Timestamp"] = pd.to_datetime(df["Timestamp"])

        return df

    except Exception as e:

        st.error(f"Unable to load authentication alerts: {e}")

        return pd.DataFrame()
def render_sidebar() -> str:
    with st.sidebar:
        st.title("CyberShield")
        st.caption("Security Operations Platform")

        page = st.radio(
            "Navigation",
            [
                "🏠 Executive Overview",
                "🌐 URL Threat Detection",
                "🔐 Authentication Monitoring",
                "📈 Threat Intelligence",
                "📊 SHAP Explainability",
                "🛡 Vulnerability Assessment",
                "📄 Investigation Report",
                "⚙ System Status",
            ],
        )

        st.divider()

        if st.session_state["url_model_loaded"]:
            st.success("URL model active")
            st.caption(st.session_state["url_model_source"])
        else:
            st.warning("URL model not loaded")

        st.caption(f"Scans this session: {len(st.session_state['assessments'])}")

    return page


def section(title: str) -> None:
    st.markdown(f'<div class="section-title">{title}</div>', unsafe_allow_html=True)
def page_system_status():

    section("System Status")

    st.subheader("Application Components")

    components = [

        [
            "URL XGBoost Model",
            URL_MODEL_PATH.exists()
        ],

        [
            "Authentication XGBoost Model",
            AUTH_MODEL_PATH.exists()
        ],

        [
            "Authentication Alerts",
            AUTH_ALERT_FILE.exists()
        ],

        [
            "URL Label Encoder",
            URL_LABEL_ENCODER_PATH.exists()
        ],

        [
            "Authentication Label Encoder",
            AUTH_ENCODER_PATH.exists()
        ]

    ]

    df = pd.DataFrame(

        components,

        columns=[

            "Component",

            "Available"

        ]

    )

    st.dataframe(

        df,

        use_container_width=True,

        hide_index=True

    )

    st.subheader("Project Information")

    st.info(
        """
CyberShield SOC Platform

Version : 2.0

Modules

• URL Threat Detection (XGBoost)

• Authentication Threat Detection (XGBoost)

• SHAP Explainability

• Vulnerability Assessment

• Threat Intelligence

• Investigation Reports
"""
    )

def render_metric(label: str, value: str, help_text: str = "") -> None:
    st.markdown(
        f"""
        <div class="metric-card">
            <div style="font-size:.75rem;color:#94a3b8;text-transform:uppercase">{label}</div>
            <div style="font-size:1.6rem;font-weight:700">{value}</div>
            <div style="font-size:.75rem;color:#64748b">{help_text}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def chart_risk_trend(assessments: list[dict[str, Any]]) -> go.Figure | None:
    if not assessments:
        return None

    frame = pd.DataFrame(assessments)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"])
    grouped = frame.groupby(["timestamp", "risk_label"]).size().reset_index(name="count")

    fig = go.Figure()
    for label, color in RISK_COLORS.items():
        subset = grouped[grouped["risk_label"] == label]
        if not subset.empty:
            fig.add_trace(go.Scatter(
                x=subset["timestamp"],
                y=subset["count"],
                mode="lines+markers",
                name=label,
                line=dict(color=color),
            ))

    fig.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20))
    return fig


def chart_probabilities(probabilities: dict[str, float]) -> go.Figure:
    fig = go.Figure(go.Bar(
        x=[value * 100 for value in probabilities.values()],
        y=list(probabilities.keys()),
        orientation="h",
        marker_color=[RISK_COLORS[label] for label in probabilities.keys()],
        text=[f"{value * 100:.1f}%" for value in probabilities.values()],
        textposition="outside",
    ))
    fig.update_layout(height=220, xaxis_range=[0, 110], margin=dict(l=20, r=20, t=30, b=20))
    return fig


def chart_vulnerabilities(vulnerabilities: list[dict[str, str]]) -> go.Figure:
    counts = {
        severity: sum(1 for finding in vulnerabilities if finding["severity"] == severity)
        for severity in ["critical", "high", "medium", "low"]
    }

    fig = go.Figure(go.Bar(
        x=["Critical", "High", "Medium", "Low"],
        y=[counts["critical"], counts["high"], counts["medium"], counts["low"]],
        marker_color=["#dc2626", "#ef4444", "#f59e0b", "#22c55e"],
        text=list(counts.values()),
        textposition="outside",
    ))
    fig.update_layout(height=260, margin=dict(l=20, r=20, t=30, b=20))
    return fig


def page_overview() -> None:

    section("Executive Overview")

    # ==========================================================
    # Load Data
    # ==========================================================

    url_assessments = st.session_state.get("assessments", [])

    auth_df = load_authentication_alerts()

    total_url_scans = len(url_assessments)

    total_auth_events = len(auth_df)

    high_url = sum(
        1
        for item in url_assessments
        if item["risk_label"] == "High Risk"
    )

    medium_url = sum(
        1
        for item in url_assessments
        if item["risk_label"] == "Medium Risk"
    )

    low_url = sum(
        1
        for item in url_assessments
        if item["risk_label"] == "Low Risk"
    )

    high_auth = 0
    critical_auth = 0

    if not auth_df.empty and "Risk" in auth_df.columns:

        high_auth = len(
            auth_df[auth_df["Risk"] == "High"]
        )

        critical_auth = len(
            auth_df[auth_df["Risk"] == "Critical"]
        )

    # ==========================================================
    # KPI Cards
    # ==========================================================

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "URL Scans",
        total_url_scans
    )

    c2.metric(
        "Authentication Events",
        total_auth_events
    )

    c3.metric(
        "High URL Threats",
        high_url
    )

    c4.metric(
        "Critical Auth Alerts",
        critical_auth
    )

    st.divider()

    # ==========================================================
    # Risk Comparison
    # ==========================================================

    left, right = st.columns(2)

    with left:

        st.subheader("URL Threat Distribution")

        if total_url_scans > 0:

            url_chart = pd.DataFrame({

                "Risk": [
                    "High",
                    "Medium",
                    "Low"
                ],

                "Count": [
                    high_url,
                    medium_url,
                    low_url
                ]

            })

            fig = px.pie(
                url_chart,
                names="Risk",
                values="Count",
                hole=0.45,
                title="URL Threats"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        else:

            st.info("No URL scans available.")

    with right:

        st.subheader("Authentication Risk Distribution")

        if (
            not auth_df.empty
            and "Risk" in auth_df.columns
        ):

            auth_chart = (

                auth_df["Risk"]

                .value_counts()

                .reset_index()

            )

            auth_chart.columns = [

                "Risk",

                "Count"

            ]

            fig = px.bar(

                auth_chart,

                x="Risk",

                y="Count",

                text="Count",

                title="Authentication Alerts"

            )

            st.plotly_chart(

                fig,

                use_container_width=True

            )

        else:

            st.info("No authentication alerts available.")

    st.divider()

    # ==========================================================
    # Recent Activity
    # ==========================================================

    st.subheader("Recent Authentication Alerts")

    if auth_df.empty:

        st.info("No authentication events.")

    else:

        preview = auth_df.copy()

        if "Timestamp" in preview.columns:

            preview = preview.sort_values(
                by="Timestamp",
                ascending=False
            )

        st.dataframe(

            preview.head(10),

            use_container_width=True,

            hide_index=True

        )

    st.divider()

    # ==========================================================
    # Recent URL Assessments
    # ==========================================================

    st.subheader("Recent URL Assessments")

    if total_url_scans == 0:

        st.info("No URL assessments.")

    else:

        st.dataframe(

            pd.DataFrame(url_assessments).tail(10),

            use_container_width=True,

            hide_index=True

        )

def page_scanner() -> None:
    section("URL Scanner")

    try:
        ensure_url_model()
    except URLModelError as exc:
        st.error("URL model could not be loaded.")
        st.code(str(exc))
        return

    url = st.text_input("Target URL", placeholder="https://example.com")

    col1, col2 = st.columns([1, 1])
    scan = col1.button("Run Assessment", type="primary", use_container_width=True)
    clear = col2.button("Clear Result", use_container_width=True)

    if clear:
        st.session_state["scan_result"] = None
        st.rerun()

    if scan:
        if not url.strip():
            st.warning("Enter a URL first.")
            return

        clean_url = url.strip()
        if not clean_url.startswith(("http://", "https://")):
            clean_url = "https://" + clean_url

        run_scan(clean_url)

    result = st.session_state.get("scan_result")
    if result:
        render_scan_result(result)


def render_scan_result(result: dict[str, Any]) -> None:
    prediction = result["prediction"]
    vulnerabilities = result["vulnerabilities"]
    features = result["features"]
    risk_color = RISK_COLORS[prediction["label"]]

    st.markdown(
        f"""
        <div class="metric-card" style="border-left: 5px solid {risk_color}">
            <div style="font-size:.75rem;color:#94a3b8;text-transform:uppercase">Threat Classification</div>
            <div style="font-size:2rem;font-weight:700;color:{risk_color}">{prediction["label"]}</div>
            <div>Confidence: {prediction["confidence"] * 100:.1f}%</div>
            <div style="word-break:break-all;color:#94a3b8">{result["url"]}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.plotly_chart(chart_probabilities(prediction["probabilities"]), use_container_width=True)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        render_metric("SSL", "Valid" if result["ssl"].get("valid") else "Invalid")
    with col2:
        render_metric("Domain Age", f"{result['whois'].get('age_days', features['domain_age_days'])} days")
    with col3:
        missing_headers = sum(features[name] for name in [
            "missing_hsts", "missing_csp", "missing_xframe", "missing_xcontent", "missing_referrer"
        ])
        render_metric("Security Headers", f"{5 - missing_headers}/5")
    with col4:
        render_metric("Findings", str(len(vulnerabilities)))

    tabs = st.tabs(["Features", "Vulnerabilities", "Live Checks"])

    with tabs[0]:
        display_features = pd.DataFrame([
            {"Feature": name, "Value": features[name]}
            for name in URL_FEATURE_NAMES
        ])
        st.dataframe(display_features, use_container_width=True, hide_index=True)

    with tabs[1]:
        if vulnerabilities:
            for finding in vulnerabilities:
                st.markdown(
                    f"""
                    <div class="finding {finding["severity"]}">
                        <strong>{finding["severity"].upper()} - {finding["title"]}</strong><br>
                        {finding["description"]}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.success("No vulnerability rule findings.")

    with tabs[2]:
        st.json({
            "ssl": result["ssl"],
            "headers": result["headers"],
            "whois": result["whois"],
            "tags": features.get("_threat_tags", []),
        })


def page_threat_detection() -> None:
    section("Threat Detection")

    st.info(
        "This page summarizes URL scan signals only. "
        "It does not load or reuse authentication models."
    )

    assessments = st.session_state["assessments"]
    if not assessments:
        st.info("No URL threat events yet.")
        return

    frame = pd.DataFrame(assessments)
    st.dataframe(frame.tail(50), use_container_width=True, hide_index=True)


def page_authentication() -> None:
    section("Authentication Threat Detection")

    st.caption(
        "Live authentication monitoring using the XGBoost authentication model."
    )

    df = load_authentication_alerts()

    if df.empty:
        st.warning("No authentication alerts available.")
        st.info(
            "Run windows_event_monitor.py to generate authentication events."
        )
        return

    # -------------------------------------------------------
    # KPI Cards
    # -------------------------------------------------------

    total_events = len(df)

    high_risk = (
        len(df[df["Risk"] == "High"])
        if "Risk" in df.columns
        else 0
    )

    critical = (
        len(df[df["Risk"] == "Critical"])
        if "Risk" in df.columns
        else 0
    )

    avg_confidence = (
        round(df["Confidence"].mean(), 2)
        if "Confidence" in df.columns
        else 0
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Events", total_events)
    c2.metric("Critical Alerts", critical)
    c3.metric("High Risk", high_risk)
    c4.metric("Avg Confidence", f"{avg_confidence}%")

    st.divider()

    # -------------------------------------------------------
    # Charts
    # -------------------------------------------------------

    left, right = st.columns(2)

    with left:

        st.subheader("Risk Distribution")

        if "Risk" in df.columns:

            risk = (
                df["Risk"]
                .value_counts()
                .reset_index()
            )

            risk.columns = ["Risk", "Count"]

            fig = px.pie(
                risk,
                names="Risk",
                values="Count",
                hole=0.45
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

    with right:

        st.subheader("Prediction Distribution")

        if "Prediction" in df.columns:

            pred = (
                df["Prediction"]
                .value_counts()
                .reset_index()
            )

            pred.columns = ["Prediction", "Count"]

            fig = px.bar(
                pred,
                x="Prediction",
                y="Count",
                text="Count"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

    st.divider()

    # -------------------------------------------------------
    # Timeline
    # -------------------------------------------------------

    if "Timestamp" in df.columns:

        st.subheader("Authentication Timeline")

        timeline = df.copy()

        timeline["Minute"] = (
            timeline["Timestamp"]
            .dt.floor("min")
        )

        timeline = (
            timeline
            .groupby("Minute")
            .size()
            .reset_index(name="Events")
        )

        fig = px.line(
            timeline,
            x="Minute",
            y="Events",
            markers=True
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    st.divider()

    # -------------------------------------------------------
    # Recent Alerts
    # -------------------------------------------------------

    st.subheader("Recent Authentication Alerts")

    table = df.copy()

    if "Timestamp" in table.columns:

        table["Timestamp"] = (
            table["Timestamp"]
            .astype(str)
        )

    st.dataframe(
        table.sort_values(
            by="Timestamp",
            ascending=False
        ),
        use_container_width=True,
        hide_index=True,
        height=500
    )

    csv = table.to_csv(index=False).encode("utf-8")

    st.download_button(
        "Download Authentication Alerts",
        data=csv,
        file_name="authentication_alerts.csv",
        mime="text/csv"
    )

def page_shap() -> None:
    section("SHAP Explainability")

    result = st.session_state.get("scan_result")
    if not result:
        st.info("Run a URL scan first.")
        return

    shap_result = result.get("shap")
    if not shap_result or shap_result.get("error"):
        st.warning("SHAP values are unavailable for this scan.")
        if shap_result and shap_result.get("error"):
            st.code(shap_result["error"])
        return

    top_features = shap_result["top_features"][:15]
    if not top_features:
        st.info("No SHAP feature contributions were returned.")
        return

    frame = pd.DataFrame(top_features, columns=["Feature", "SHAP Value"])
    st.dataframe(frame, use_container_width=True, hide_index=True)

    fig = go.Figure(go.Bar(
        x=frame["SHAP Value"],
        y=frame["Feature"],
        orientation="h",
        marker_color=["#ef4444" if value > 0 else "#22c55e" for value in frame["SHAP Value"]],
    ))
    fig.update_layout(height=420, margin=dict(l=20, r=20, t=30, b=20))
    st.plotly_chart(fig, use_container_width=True)


def page_vulnerability_assessment() -> None:
    section("Vulnerability Assessment")

    result = st.session_state.get("scan_result")
    if not result:
        st.info("Run a URL scan first.")
        return

    vulnerabilities = result["vulnerabilities"]
    st.plotly_chart(chart_vulnerabilities(vulnerabilities), use_container_width=True)

    if not vulnerabilities:
        st.success("No vulnerabilities detected.")
        return

    for finding in vulnerabilities:
        st.markdown(
            f"""
            <div class="finding {finding["severity"]}">
                <strong>{finding["severity"].upper()} - {finding["title"]}</strong><br>
                {finding["description"]}
            </div>
            """,
            unsafe_allow_html=True,
        )


def build_investigation_report(result: dict[str, Any]) -> pd.DataFrame:
    prediction = result["prediction"]
    features = result["features"]

    rows = [
        {"Field": "URL", "Value": result["url"]},
        {"Field": "Timestamp", "Value": result["timestamp"]},
        {"Field": "Risk Label", "Value": prediction["label"]},
        {"Field": "Confidence", "Value": f"{prediction['confidence'] * 100:.1f}%"},
        {"Field": "URL Hash", "Value": features["_url_hash"]},
        {"Field": "Finding Count", "Value": len(result["vulnerabilities"])},
    ]

    for finding in result["vulnerabilities"]:
        rows.append({
            "Field": f"{finding['severity'].upper()} Finding",
            "Value": f"{finding['title']} - {finding['description']}",
        })

    return pd.DataFrame(rows)


def page_report() -> None:
    section("Investigation Report")

    result = st.session_state.get("scan_result")
    if not result:
        st.info("Run a URL scan first.")
        return

    report = build_investigation_report(result)
    st.dataframe(report, use_container_width=True, hide_index=True)

    csv = report.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download CSV Report",
        data=csv,
        file_name=f"cybershield_report_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
    )


def page_intelligence() -> None:

    section("Threat Intelligence")

    url_data = st.session_state.get("assessments", [])

    auth_df = load_authentication_alerts()

    # =====================================================
    # Overall Statistics
    # =====================================================

    total_url = len(url_data)
    total_auth = len(auth_df)

    total_events = total_url + total_auth

    st.subheader("SOC Threat Summary")

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "URL Threats",
        total_url
    )

    c2.metric(
        "Authentication Threats",
        total_auth
    )

    c3.metric(
        "Total Threat Events",
        total_events
    )

    st.divider()

    # =====================================================
    # URL Threat Intelligence
    # =====================================================

    left, right = st.columns(2)

    with left:

        st.subheader("URL Risk Distribution")

        if total_url:

            url_df = pd.DataFrame(url_data)

            counts = (

                url_df["risk_label"]

                .value_counts()

                .reset_index()

            )

            counts.columns = [

                "Risk",

                "Count"

            ]

            fig = px.pie(

                counts,

                names="Risk",

                values="Count",

                hole=0.45

            )

            st.plotly_chart(

                fig,

                use_container_width=True

            )

        else:

            st.info("No URL intelligence available.")

    with right:

        st.subheader("Authentication Risk Distribution")

        if (

            not auth_df.empty

            and "Risk" in auth_df.columns

        ):

            counts = (

                auth_df["Risk"]

                .value_counts()

                .reset_index()

            )

            counts.columns = [

                "Risk",

                "Count"

            ]

            fig = px.bar(

                counts,

                x="Risk",

                y="Count",

                text="Count"

            )

            st.plotly_chart(

                fig,

                use_container_width=True

            )

        else:

            st.info("No authentication intelligence available.")

    st.divider()

    # =====================================================
    # Authentication Prediction Distribution
    # =====================================================

    st.subheader("Authentication Prediction Distribution")

    if (

        not auth_df.empty

        and "Prediction" in auth_df.columns

    ):

        pred = (

            auth_df["Prediction"]

            .value_counts()

            .reset_index()

        )

        pred.columns = [

            "Prediction",

            "Count"

        ]

        fig = px.bar(

            pred,

            x="Prediction",

            y="Count",

            text="Count",

            color="Prediction"

        )

        st.plotly_chart(

            fig,

            use_container_width=True

        )

    else:

        st.info("Prediction data unavailable.")

    st.divider()

    # =====================================================
    # Authentication Confidence
    # =====================================================

    st.subheader("Authentication Confidence")

    if (

        not auth_df.empty

        and "Confidence" in auth_df.columns

    ):

        fig = px.histogram(

            auth_df,

            x="Confidence",

            nbins=20

        )

        st.plotly_chart(

            fig,

            use_container_width=True

        )

    else:

        st.info("Confidence data unavailable.")

    st.divider()

    # =====================================================
    # Recent Threats
    # =====================================================

    col1, col2 = st.columns(2)

    with col1:

        st.subheader("Recent URL Threats")

        if total_url:

            st.dataframe(

                pd.DataFrame(url_data).tail(10),

                use_container_width=True,

                hide_index=True

            )

        else:

            st.info("No URL threats.")

    with col2:

        st.subheader("Recent Authentication Threats")

        if not auth_df.empty:

            table = auth_df.copy()

            if "Timestamp" in table.columns:

                table = table.sort_values(

                    by="Timestamp",

                    ascending=False

                )

            st.dataframe(

                table.head(10),

                use_container_width=True,

                hide_index=True

            )

        else:

            st.info("No authentication threats.")

    st.divider()

    # =====================================================
    # Threat Intelligence Report
    # =====================================================

    report = pd.DataFrame({

        "Category": [

            "URL Threats",

            "Authentication Threats",

            "Total Threat Events"

        ],

        "Count": [

            total_url,

            total_auth,

            total_events

        ]

    })

    st.subheader("Threat Intelligence Summary")

    st.dataframe(

        report,

        use_container_width=True,

        hide_index=True

    )

    csv = report.to_csv(index=False).encode("utf-8")

    st.download_button(

        "Download Threat Intelligence Report",

        data=csv,

        file_name="threat_intelligence_report.csv",

        mime="text/csv"

    )

def main() -> None:
    configure_page()
    init_session_state()

    try:
        ensure_url_model()
    except URLModelError:
        pass

    page = render_sidebar()

    pages = {
       "🏠 Executive Overview":
        page_overview,

    "🌐 URL Threat Detection":
        page_scanner,

    "🔐 Authentication Monitoring":
        page_authentication,

    "📈 Threat Intelligence":
        page_intelligence,

    "📊 SHAP Explainability":
        page_shap,

    "🛡 Vulnerability Assessment":
        page_vulnerability_assessment,

    "📄 Investigation Report":
        page_report,

    "⚙ System Status":
        page_system_status
    }

    pages[page]()


if __name__ == "__main__":
    main()
    
