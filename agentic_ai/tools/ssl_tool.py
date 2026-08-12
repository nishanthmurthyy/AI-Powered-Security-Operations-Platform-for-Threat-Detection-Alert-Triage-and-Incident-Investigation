"""
SSL Certificate Investigation Tool

Collects SSL certificate information for URL investigations.

Information Collected:
- SSL Validity
- Issuer
- Subject
- TLS Version
- Expiration Date
- Days Remaining

Author: Sandra Jane MSc Project
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


class SSLTool:

    def __init__(self):
        pass

    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL."""

        if url.startswith(("http://", "https://")):
            return urlparse(url).hostname

        return url

    def check(self, url: str):
        """
        Retrieve SSL certificate information.

        Parameters
        ----------
        url : str

        Returns
        -------
        dict
        """

        hostname = self._extract_hostname(url)

        result = {
            "hostname": hostname,
            "ssl_valid": False,
            "issuer": "Unknown",
            "subject": "Unknown",
            "expires": None,
            "days_remaining": None,
            "tls_version": None,
            "error": None
        }

        try:

            context = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=10) as sock:

                with context.wrap_socket(sock, server_hostname=hostname) as secure_socket:

                    certificate = secure_socket.getpeercert()

                    result["ssl_valid"] = True

                    result["tls_version"] = secure_socket.version()

                    # Subject
                    subject = dict(x[0] for x in certificate.get("subject", []))
                    result["subject"] = subject.get("commonName", "Unknown")

                    # Issuer
                    issuer = dict(x[0] for x in certificate.get("issuer", []))
                    result["issuer"] = issuer.get("commonName", "Unknown")

                    # Expiration
                    expiry = certificate.get("notAfter")

                    if expiry:

                        expiry_date = datetime.strptime(
                            expiry,
                            "%b %d %H:%M:%S %Y %Z"
                        )

                        result["expires"] = expiry_date.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )

                        result["days_remaining"] = (
                            expiry_date - datetime.utcnow()
                        ).days

        except Exception as e:

            result["error"] = str(e)

        return result


ssl_tool = SSLTool()


def check_ssl(url: str):
    """
    Convenience wrapper.
    """
    return ssl_tool.check(url)