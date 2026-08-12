"""
=============================================================================
PHASE 3 — Authentication Risk Engine
=============================================================================
Project : AI-Powered Security Operations Platform
Module  : Authentication Monitoring — Rule-Based Risk Engine

Architecture
------------
This module is a PURE RULE-BASED ENGINE.
It does NOT use XGBoost, the GUIDE dataset, or any machine learning model.
It is completely independent of the Threat Detection module.

Input
-----
Single login event dict or function arguments covering:
  username, ip_address, computer, auth_type, login_time,
  failed_attempts, is_admin, new_device, result

Risk Scoring Rules
------------------
Rule                          Points
─────────────────────────────────────
Failed Login                    +20
Repeated Failed Attempts        +25
Admin Account Login             +20
Unknown / New Device            +15
Off-Hours Access                +10
NTLM Authentication             +10
Multiple Consecutive Failures   +15
Impossible Travel Flag          +20
Known Malicious IP              +30

Risk Levels
-----------
Score   Severity
0–20    Low
21–45   Medium
46–70   High
71–100  Critical

Output
------
{
  "Username", "Computer", "IP Address", "Risk Score", "Severity",
  "Status", "Findings", "Timestamp"
}
=============================================================================
"""

import datetime
import os
import json
import csv
from typing import Optional

# ---------------------------------------------------------------------------
# RISK SCORING WEIGHTS
# ---------------------------------------------------------------------------

RISK_WEIGHTS: dict[str, int] = {
    "failed_login":             20,
    "repeated_failures":        25,
    "admin_account":            20,
    "new_device":               15,
    "off_hours":                10,
    "ntlm_auth":                10,
    "multiple_failures":        15,
    "impossible_travel":        20,
    "malicious_ip":             30,
}

# ---------------------------------------------------------------------------
# RISK THRESHOLDS → SEVERITY
# ---------------------------------------------------------------------------

def _severity(score: int) -> tuple[str, str]:
    """
    Map numeric risk score to (severity_label, status_message).

    Returns
    -------
    tuple: (severity, status)
    """
    if score <= 20:
        return "Low",      "Normal Authentication"
    if score <= 45:
        return "Medium",   "Suspicious Login — Review Recommended"
    if score <= 70:
        return "High",     "High-Risk Login — Immediate Review Required"
    return   "Critical",  "Critical Risk — Potential Attack Detected"


# ---------------------------------------------------------------------------
# HELPER — BUSINESS HOURS CHECK
# ---------------------------------------------------------------------------

BUSINESS_START = 8    # 08:00
BUSINESS_END   = 18   # 18:00


def _is_off_hours(login_time: str) -> bool:
    """
    Return True if the login time falls outside business hours (08:00–18:00).

    Parameters
    ----------
    login_time : "HH:MM" string (24-hour format)
    """
    try:
        hour = datetime.datetime.strptime(login_time.strip(), "%H:%M").hour
        return hour < BUSINESS_START or hour >= BUSINESS_END
    except (ValueError, AttributeError):
        # If we cannot parse the time, treat as off-hours (conservative)
        return True


# ---------------------------------------------------------------------------
# CORE RISK ENGINE
# ---------------------------------------------------------------------------

def evaluate_login(
    username:          str,
    ip_address:        str,
    computer:          str,
    auth_type:         str,
    login_time:        str,             # "HH:MM"
    failed_attempts:   int   = 0,
    is_admin:          bool  = False,
    new_device:        bool  = False,
    result:            str   = "Success",
    impossible_travel: bool  = False,
    malicious_ip:      bool  = False,
) -> dict:
    """
    Evaluate a single authentication event and produce a structured risk report.

    Parameters
    ----------
    username          : account identifier (e.g. "U1@DOM")
    ip_address        : source IP address
    computer          : destination computer
    auth_type         : e.g. "Kerberos", "NTLM", "Negotiate"
    login_time        : "HH:MM" string
    failed_attempts   : number of consecutive failed logins for this user
    is_admin          : True if the account has administrative privileges
    new_device        : True if the source device is unrecognised
    result            : "Success" or "Fail"
    impossible_travel : True if login location is physically implausible
    malicious_ip      : True if IP appears in threat-intelligence feeds

    Returns
    -------
    dict: risk report with Username, Computer, Risk Score, Severity, etc.
    """
    score    = 0
    findings = []

    # ── Rule 1: Failed login ──────────────────────────────────────────────
    if str(result).strip().lower() in ("fail", "failure", "failed"):
        score += RISK_WEIGHTS["failed_login"]
        findings.append(
            f"Failed login detected (result='{result}')"
        )

    # ── Rule 2: Repeated failed attempts ─────────────────────────────────
    if failed_attempts >= 5:
        score += RISK_WEIGHTS["repeated_failures"]
        findings.append(
            f"Repeated failed attempts: {failed_attempts} failures"
        )

    # ── Rule 3: Multiple consecutive failures (lower threshold) ──────────
    elif 2 <= failed_attempts < 5:
        score += RISK_WEIGHTS["multiple_failures"]
        findings.append(
            f"Multiple failed attempts: {failed_attempts}"
        )

    # ── Rule 4: Admin account ─────────────────────────────────────────────
    if is_admin:
        score += RISK_WEIGHTS["admin_account"]
        findings.append(
            f"Privileged / admin account accessed: {username}"
        )

    # ── Rule 5: New / unknown device ─────────────────────────────────────
    if new_device:
        score += RISK_WEIGHTS["new_device"]
        findings.append(
            f"Login from unrecognised device / computer: {computer}"
        )

    # ── Rule 6: Off-hours access ─────────────────────────────────────────
    if _is_off_hours(login_time):
        score += RISK_WEIGHTS["off_hours"]
        findings.append(
            f"Off-hours login detected at {login_time} "
            f"(business hours: {BUSINESS_START:02d}:00–{BUSINESS_END:02d}:00)"
        )

    # ── Rule 7: NTLM authentication ──────────────────────────────────────
    if str(auth_type).strip().upper() == "NTLM":
        score += RISK_WEIGHTS["ntlm_auth"]
        findings.append(
            "NTLM authentication used — older protocol with known weaknesses"
        )

    # ── Rule 8: Impossible travel ─────────────────────────────────────────
    if impossible_travel:
        score += RISK_WEIGHTS["impossible_travel"]
        findings.append(
            "Impossible travel: authentication from geographically distant locations"
        )

    # ── Rule 9: Known malicious IP ───────────────────────────────────────
    if malicious_ip:
        score += RISK_WEIGHTS["malicious_ip"]
        findings.append(
            f"Source IP {ip_address} flagged in threat-intelligence feeds"
        )

    # ── Cap score at 100 ─────────────────────────────────────────────────
    score = min(score, 100)

    severity, status = _severity(score)

    return {
        "Username":   username,
        "IP Address": ip_address,
        "Computer":   computer,
        "Auth Type":  auth_type,
        "Login Time": login_time,
        "Risk Score": score,
        "Severity":   severity,
        "Status":     status,
        "Findings":   findings,
        "Timestamp":  datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


# ---------------------------------------------------------------------------
# BATCH EVALUATION
# ---------------------------------------------------------------------------

def evaluate_batch(events: list[dict]) -> list[dict]:
    """
    Evaluate a list of login event dicts.
    Each dict must contain the same keys as evaluate_login's parameters.

    Returns
    -------
    list of risk-report dicts
    """
    results = []
    for event in events:
        try:
            report = evaluate_login(**event)
            results.append(report)
        except TypeError as exc:
            results.append({
                "Username": event.get("username", "Unknown"),
                "Error":    str(exc),
                "Timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            })
    return results


# ---------------------------------------------------------------------------
# REPORT GENERATORS
# ---------------------------------------------------------------------------

def to_dict(report: dict) -> dict:
    """Return a flat dict suitable for CSV / DataFrame row."""
    return {
        "Timestamp":  report.get("Timestamp", ""),
        "Username":   report.get("Username",  ""),
        "IP Address": report.get("IP Address",""),
        "Computer":   report.get("Computer",  ""),
        "Auth Type":  report.get("Auth Type", ""),
        "Login Time": report.get("Login Time",""),
        "Risk Score": report.get("Risk Score", 0),
        "Severity":   report.get("Severity",  ""),
        "Status":     report.get("Status",    ""),
        "Findings":   "; ".join(report.get("Findings", [])),
    }


def save_to_csv(reports: list[dict], filepath: str) -> None:
    """Append risk reports to a CSV file."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    fieldnames = [
        "Timestamp", "Username", "IP Address", "Computer",
        "Auth Type", "Login Time", "Risk Score", "Severity", "Status", "Findings",
    ]
    file_exists = os.path.isfile(filepath)
    with open(filepath, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        for r in reports:
            writer.writerow(to_dict(r))


# ---------------------------------------------------------------------------
# DEMO — standalone test
# ---------------------------------------------------------------------------

def _demo() -> None:
    print("=" * 60)
    print(" PHASE 3 — Authentication Risk Engine (Demo)")
    print("=" * 60)

    test_events = [
        dict(username="U1@DOM", ip_address="10.0.0.1",  computer="C1",
             auth_type="Kerberos", login_time="09:15",
             failed_attempts=0,  is_admin=False, new_device=False),
        dict(username="U2@DOM", ip_address="10.0.0.5",  computer="C2",
             auth_type="NTLM",    login_time="02:45",
             failed_attempts=6,  is_admin=True,  new_device=True),
        dict(username="U3@DOM", ip_address="185.1.2.3", computer="C3",
             auth_type="NTLM",    login_time="23:10",
             failed_attempts=3,  is_admin=False, new_device=True,
             malicious_ip=True, result="Fail"),
    ]

    for event in test_events:
        report = evaluate_login(**event)
        print(f"\n  User     : {report['Username']}")
        print(f"  Score    : {report['Risk Score']}/100")
        print(f"  Severity : {report['Severity']}")
        print(f"  Status   : {report['Status']}")
        print(f"  Findings :")
        for f in report["Findings"]:
            print(f"    • {f}")
    print("\n✓ Demo complete.")


if __name__ == "__main__":
    _demo()