"""
URL Investigation Agent

Performs an end-to-end investigation of suspicious URLs.

Workflow
--------
1. Receive ML prediction
2. Collect evidence
3. Calculate risk score
4. Return structured investigation report

Author: Sandra Jane MSc Project
"""

from agentic_ai.tools.ssl_tool import check_ssl
from agentic_ai.tools.whois_tool import lookup_whois
from agentic_ai.tools.dns_tool import lookup_dns
from agentic_ai.tools.threat_intelligence_tool import (
    lookup_threat_intelligence,
)


class URLInvestigationAgent:

    def __init__(self):
        pass

    def investigate(
        self,
        url: str,
        prediction: str,
        confidence: float,
        feature_values: dict = None,
    ):

        report = {
            "url": url,
            "prediction": prediction,
            "confidence": confidence,
            "feature_values": feature_values or {},
            "evidence": {},
            "risk_score": 0,
            "risk_level": "Low",
            "recommendations": [],
        }

        # ------------------------------------------
        # Skip Investigation if URL is Benign
        # ------------------------------------------

        if prediction.lower() != "malicious":

            report["message"] = (
                "URL classified as Benign. Investigation skipped."
            )

            return report

        print("\n========== URL INVESTIGATION ==========\n")

        # ------------------------------------------
        # SSL Investigation
        # ------------------------------------------

        print("[+] Checking SSL Certificate...")

        ssl_result = check_ssl(url)

        report["evidence"]["ssl"] = ssl_result

        # ------------------------------------------
        # WHOIS Investigation
        # ------------------------------------------

        print("[+] Collecting WHOIS Information...")

        whois_result = lookup_whois(url)

        report["evidence"]["whois"] = whois_result

        # ------------------------------------------
        # DNS Investigation
        # ------------------------------------------

        print("[+] Performing DNS Lookup...")

        dns_result = lookup_dns(url)

        report["evidence"]["dns"] = dns_result

        # ------------------------------------------
        # Threat Intelligence
        # ------------------------------------------

        print("[+] Querying Threat Intelligence...")

        ti_result = lookup_threat_intelligence(url)

        report["evidence"]["threat_intelligence"] = ti_result

        # ------------------------------------------
        # Risk Scoring
        # ------------------------------------------

        risk = 0

        # ML Confidence

        if confidence >= 95:
            risk += 40

        elif confidence >= 85:
            risk += 30

        elif confidence >= 75:
            risk += 20

        else:
            risk += 10

        # SSL

        if not ssl_result.get("ssl_valid", False):

            risk += 20

            report["recommendations"].append(
                "Investigate invalid SSL certificate."
            )

        # Domain Age

        age = whois_result.get("domain_age_days")

        if age is not None:

            if age < 30:

                risk += 25

                report["recommendations"].append(
                    "Recently registered domain."
                )

            elif age < 180:

                risk += 10

        # DNS

        if len(dns_result.get("A", [])) == 0:

            risk += 10

        # Threat Intelligence

        vt = ti_result.get("virustotal", {})

        if vt.get("enabled", False):

            risk += 10

        report["risk_score"] = min(risk, 100)

        # ------------------------------------------
        # Risk Level
        # ------------------------------------------

        if report["risk_score"] >= 80:

            report["risk_level"] = "Critical"

        elif report["risk_score"] >= 60:

            report["risk_level"] = "High"

        elif report["risk_score"] >= 40:

            report["risk_level"] = "Medium"

        else:

            report["risk_level"] = "Low"

        # ------------------------------------------
        # Generic Recommendations
        # ------------------------------------------

        report["recommendations"].extend(
            [
                "Block URL in Secure Web Gateway.",
                "Blacklist domain.",
                "Monitor proxy logs.",
                "Search SIEM for related activity.",
            ]
        )

        print("\n========== Investigation Completed ==========\n")

        return report


url_agent = URLInvestigationAgent()