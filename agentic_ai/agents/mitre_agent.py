"""
MITRE ATT&CK Mapping Agent

Maps detected threats to MITRE ATT&CK techniques.

This agent is called after:
- URL Investigation
- Authentication Investigation
- Windows Event Investigation

Author: Sandra Jane MSc Project
"""

from typing import Dict, List


class MITREAgent:

    def __init__(self):

        # Knowledge base
        self.techniques = {

            # -----------------------------
            # URL Threats
            # -----------------------------
            "credential_phishing": {
                "technique": "T1566.002",
                "name": "Phishing: Spearphishing Link",
                "tactic": "Initial Access",
                "severity": "High"
            },

            "malicious_url": {
                "technique": "T1204.001",
                "name": "User Execution: Malicious Link",
                "tactic": "Execution",
                "severity": "High"
            },

            "open_redirect": {
                "technique": "T1189",
                "name": "Drive-by Compromise",
                "tactic": "Initial Access",
                "severity": "Medium"
            },

            # -----------------------------
            # Authentication Threats
            # -----------------------------
            "brute_force": {
                "technique": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "severity": "Critical"
            },

            "password_spraying": {
                "technique": "T1110.003",
                "name": "Password Spraying",
                "tactic": "Credential Access",
                "severity": "Critical"
            },

            "credential_stuffing": {
                "technique": "T1110.004",
                "name": "Credential Stuffing",
                "tactic": "Credential Access",
                "severity": "High"
            },

            "valid_accounts": {
                "technique": "T1078",
                "name": "Valid Accounts",
                "tactic": "Defense Evasion",
                "severity": "High"
            },

            "remote_login": {
                "technique": "T1021",
                "name": "Remote Services",
                "tactic": "Lateral Movement",
                "severity": "Medium"
            },

            # -----------------------------
            # Windows Events
            # -----------------------------
            "powershell": {
                "technique": "T1059.001",
                "name": "PowerShell",
                "tactic": "Execution",
                "severity": "High"
            },

            "cmd_execution": {
                "technique": "T1059.003",
                "name": "Windows Command Shell",
                "tactic": "Execution",
                "severity": "High"
            },

            "registry_modification": {
                "technique": "T1112",
                "name": "Modify Registry",
                "tactic": "Defense Evasion",
                "severity": "Medium"
            },

            "scheduled_task": {
                "technique": "T1053.005",
                "name": "Scheduled Task",
                "tactic": "Persistence",
                "severity": "Medium"
            }
        }

    def map(self, findings: List[str]) -> List[Dict]:
        """
        Map investigation findings to MITRE ATT&CK techniques.
        """

        results = []

        for finding in findings:

            finding = finding.lower()

            if finding in self.techniques:

                technique = self.techniques[finding].copy()

                technique["finding"] = finding

                results.append(technique)

        return results

    def summarize(self, mappings: List[Dict]) -> Dict:
        """
        Produce a MITRE summary.
        """

        tactics = sorted(set(item["tactic"] for item in mappings))

        techniques = sorted(set(item["technique"] for item in mappings))

        highest = "Low"

        order = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
        }

        for item in mappings:
            if order[item["severity"]] > order[highest]:
                highest = item["severity"]

        return {
            "mapped_techniques": len(mappings),
            "techniques": techniques,
            "tactics": tactics,
            "overall_severity": highest
        }


mitre_agent = MITREAgent()