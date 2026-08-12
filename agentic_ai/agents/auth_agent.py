"""
Authentication Investigation Agent

Coordinates the investigation of suspicious authentication events.

Workflow:
1. Receive XGBoost prediction
2. Collect authentication evidence
3. Calculate preliminary risk
4. Return structured investigation report
"""

from agentic_ai.tools.user_history import get_user_history
from agentic_ai.tools.failed_logins import get_failed_login_history
from agentic_ai.tools.ip_lookup import lookup_ip
from agentic_ai.tools.geo_lookup import lookup_geolocation
from agentic_ai.tools.device_lookup import lookup_device


class AuthenticationInvestigationAgent:

    def __init__(self):
        pass

    def investigate(
        self,
        auth_event: dict,
        prediction: str,
        confidence: float,
        feature_values: dict = None
    ):
        """
        Investigate a suspicious authentication event.

        Parameters
        ----------
        auth_event : dict
            Authentication event.

        prediction : str
            XGBoost prediction.

        confidence : float
            Prediction confidence.

        feature_values : dict
            Model feature values.

        Returns
        -------
        dict
        """

        report = {
            "authentication_event": auth_event,
            "prediction": prediction,
            "confidence": confidence,
            "feature_values": feature_values or {},
            "evidence": {},
            "risk_score": 0,
            "risk_level": "Low"
        }

        # Only investigate suspicious events
        if prediction.lower() != "malicious":
            report["message"] = "Authentication classified as normal."
            return report

        username = auth_event.get("username")
        ip_address = auth_event.get("ip_address")
        device = auth_event.get("device")

        print("[+] Checking User History...")
        report["evidence"]["user_history"] = get_user_history(username)

        print("[+] Checking Failed Login History...")
        report["evidence"]["failed_logins"] = get_failed_login_history(username)

        print("[+] Looking up IP Address...")
        report["evidence"]["ip"] = lookup_ip(ip_address)

        print("[+] Checking Geolocation...")
        report["evidence"]["geolocation"] = lookup_geolocation(ip_address)

        print("[+] Checking Device Information...")
        report["evidence"]["device"] = lookup_device(device)

        risk = 0

        # Model confidence
        if confidence >= 90:
            risk += 40
        elif confidence >= 80:
            risk += 30
        else:
            risk += 15

        # Failed logins
        failed = report["evidence"]["failed_logins"]

        if failed.get("failed_attempts", 0) >= 5:
            risk += 20

        # New device
        device_info = report["evidence"]["device"]

        if device_info.get("new_device", False):
            risk += 15

        # High-risk country
        geo = report["evidence"]["geolocation"]

        if geo.get("country_risk") == "High":
            risk += 20

        # VPN / Proxy / TOR
        ip = report["evidence"]["ip"]

        if ip.get("proxy", False):
            risk += 10

        if ip.get("vpn", False):
            risk += 10

        if ip.get("tor", False):
            risk += 20

        report["risk_score"] = min(risk, 100)

        if risk >= 80:
            report["risk_level"] = "Critical"
        elif risk >= 60:
            report["risk_level"] = "High"
        elif risk >= 40:
            report["risk_level"] = "Medium"
        else:
            report["risk_level"] = "Low"

        return report


auth_agent = AuthenticationInvestigationAgent()