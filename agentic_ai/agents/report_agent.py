"""
SOC Report Generation Agent

Combines investigation results from all agents into
a standardized SOC Incident Report.

Author: Sandra Jane MSc Project
"""

from datetime import datetime


class ReportAgent:

    def __init__(self):
        pass

    def generate(
        self,
        incident_type: str,
        target: str,
        investigation: dict,
        mitre: dict,
        llm_report: dict
    ):
        """
        Generate the final SOC investigation report.
        """

        report = {

            "incident": {

                "timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

                "type": incident_type,

                "target": target,

                "prediction":
                    investigation.get("prediction"),

                "confidence":
                    investigation.get("confidence"),

                "risk_score":
                    investigation.get("risk_score"),

                "risk_level":
                    investigation.get("risk_level")
            },

            "evidence":
                investigation.get("evidence", {}),

            "mitre_attack":
                mitre,

            "executive_summary":
                llm_report.get("summary", ""),

            "analysis":
                llm_report.get("analysis", ""),

            "recommendations":
                llm_report.get(
                    "recommendations",
                    []
                ),

            "iocs":
                llm_report.get(
                    "iocs",
                    []
                ),

            "containment":
                llm_report.get(
                    "containment",
                    []
                ),

            "status":
                "Completed"

        }

        return report


report_agent = ReportAgent()