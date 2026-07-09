"""
authentication_monitor.py
=========================
Rule-based authentication risk assessment engine.
Completely independent of the XGBoost URL model.
"""

# ==========================================================
# IMPORTS
# ==========================================================

import datetime
import pandas as pd


# ==========================================================
# RISK WEIGHTS
# ==========================================================

# Each condition adds this many points to the risk score.
RISK_WEIGHTS: dict[str, int] = {
    "failed_attempts_high":  30,   # >= 5 failed attempts
    "failed_attempts_low":   10,   # 1-4 failed attempts
    "off_hours":             15,   # login before 06:00 or after 22:00
    "new_device":            15,
    "privileged_account":    20,
    "malicious_ip":          40,
    "multiple_locations":    20,
    "impossible_travel":     30,
    "account_locked":        15,
}


# ==========================================================
# SEVERITY THRESHOLDS
# ==========================================================

def _classify(score: int) -> tuple[str, str]:
    """Return (severity, status) based on numeric risk score."""
    if score <= 20:
        return "Low",      "Authenticated Login"
    if score <= 45:
        return "Medium",   "Suspicious Login"
    if score <= 70:
        return "High",     "Potential Malicious Login"
    return   "Critical",  "Malicious Login"


# ==========================================================
# CORE EVALUATION FUNCTION
# ==========================================================

def evaluate_login(
    username: str,
    ip_address: str,
    country: str,
    login_time: str,          # "HH:MM"
    failed_attempts: int,
    new_device: bool,
    privileged_account: bool,
    malicious_ip: bool        = False,
    multiple_locations: bool  = False,
    impossible_travel: bool   = False,
    account_locked: bool      = False,
) -> dict:
    """
    Evaluate a single login event using deterministic rule-based scoring.

    Parameters
    ----------
    username            : account identifier
    ip_address          : source IP
    country             : origin country code or name
    login_time          : "HH:MM" string (24-hour)
    failed_attempts     : number of preceding failed logins
    new_device          : True if device is not in known-device list
    privileged_account  : True if the account has elevated permissions
    malicious_ip        : True if IP appears in threat-intel feeds
    multiple_locations  : True if concurrent logins from different locations
    impossible_travel   : True if location change exceeds physical travel speed
    account_locked      : True if the account is currently locked

    Returns
    -------
    dict with keys: Username, IP Address, Country, Risk Score,
                    Severity, Status, Findings
    """
    score: int      = 0
    findings: list  = []

    # ── Failed attempts ────────────────────────────────────
    if failed_attempts >= 5:
        score += RISK_WEIGHTS["failed_attempts_high"]
        findings.append(f"High failed login attempts ({failed_attempts})")
    elif failed_attempts >= 1:
        score += RISK_WEIGHTS["failed_attempts_low"]
        findings.append(f"Failed login attempts detected ({failed_attempts})")

    # ── Off-hours access ───────────────────────────────────
    try:
        hour = datetime.datetime.strptime(login_time.strip(), "%H:%M").hour
        if hour < 6 or hour > 22:
            score += RISK_WEIGHTS["off_hours"]
            findings.append(f"Login outside business hours ({login_time})")
    except ValueError:
        findings.append(f"Invalid login time format: '{login_time}'")

    # ── Device / account signals ───────────────────────────
    if new_device:
        score += RISK_WEIGHTS["new_device"]
        findings.append("Login from an unrecognised device")

    if privileged_account:
        score += RISK_WEIGHTS["privileged_account"]
        findings.append("Privileged account accessed")

    # ── Network / location signals ─────────────────────────
    if malicious_ip:
        score += RISK_WEIGHTS["malicious_ip"]
        findings.append(f"Source IP ({ip_address}) flagged as malicious")

    if multiple_locations:
        score += RISK_WEIGHTS["multiple_locations"]
        findings.append("Concurrent logins detected from multiple locations")

    if impossible_travel:
        score += RISK_WEIGHTS["impossible_travel"]
        findings.append("Impossible travel behaviour detected")

    # ── Account state ──────────────────────────────────────
    if account_locked:
        score += RISK_WEIGHTS["account_locked"]
        findings.append("Login attempt on a locked account")

    # Cap at 100
    score = min(score, 100)

    severity, status = _classify(score)

    return {
        "Username":   username,
        "IP Address": ip_address,
        "Country":    country,
        "Risk Score": score,
        "Severity":   severity,
        "Status":     status,
        "Findings":   findings,
    }


# ==========================================================
# REPORT HELPER
# ==========================================================

def generate_dataframe(result: dict) -> pd.DataFrame:
    """Convert an evaluate_login result dict to a single-row DataFrame."""
    return pd.DataFrame({
        "Username":   [result["Username"]],
        "IP Address": [result["IP Address"]],
        "Country":    [result["Country"]],
        "Risk Score": [result["Risk Score"]],
        "Severity":   [result["Severity"]],
        "Status":     [result["Status"]],
        "Findings":   ["; ".join(result["Findings"]) if result["Findings"] else "None"],
        "Timestamp":  [datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
    })