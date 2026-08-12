"""
Threat Intelligence Tool

Aggregates threat intelligence from multiple sources.

Currently Supports:
- VirusTotal (optional)
- Google Safe Browsing (optional)
- AbuseIPDB (optional)

Returns a unified result.

Author: Sandra Jane MSc Project
"""

import os
import requests


class ThreatIntelligenceTool:

    def __init__(self):

        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.gs_api_key = os.getenv("SAFE_BROWSING_API_KEY")
        self.abuse_api_key = os.getenv("ABUSEIPDB_API_KEY")

    # -------------------------------------------------------
    # VirusTotal
    # -------------------------------------------------------

    def virustotal_lookup(self, url):

        if not self.vt_api_key:

            return {
                "enabled": False,
                "message": "VirusTotal API key not configured."
            }

        return {
            "enabled": True,
            "status": "Not Implemented"
        }

    # -------------------------------------------------------
    # Google Safe Browsing
    # -------------------------------------------------------

    def safe_browsing_lookup(self, url):

        if not self.gs_api_key:

            return {
                "enabled": False,
                "message": "Google Safe Browsing API key not configured."
            }

        return {
            "enabled": True,
            "status": "Not Implemented"
        }

    # -------------------------------------------------------
    # AbuseIPDB
    # -------------------------------------------------------

    def abuseipdb_lookup(self, url):

        if not self.abuse_api_key:

            return {
                "enabled": False,
                "message": "AbuseIPDB API key not configured."
            }

        return {
            "enabled": True,
            "status": "Not Implemented"
        }

    # -------------------------------------------------------
    # Combined Investigation
    # -------------------------------------------------------

    def investigate(self, url):

        result = {

            "virustotal":
                self.virustotal_lookup(url),

            "google_safe_browsing":
                self.safe_browsing_lookup(url),

            "abuseipdb":
                self.abuseipdb_lookup(url)

        }

        return result


threat_tool = ThreatIntelligenceTool()


def lookup_threat_intelligence(url: str):

    return threat_tool.investigate(url)