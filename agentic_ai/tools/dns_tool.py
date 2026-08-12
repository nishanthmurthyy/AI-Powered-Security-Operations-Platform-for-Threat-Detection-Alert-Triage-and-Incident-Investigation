"""
DNS Lookup Tool

Performs DNS enumeration for URL investigations.

Records Collected:
- A
- AAAA
- MX
- NS
- TXT
- CNAME

Author: Sandra Jane MSc Project
"""

import dns.resolver
from urllib.parse import urlparse


class DNSTool:

    def __init__(self):
        self.resolver = dns.resolver.Resolver()

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""

        if url.startswith(("http://", "https://")):
            return urlparse(url).netloc

        return url

    def _query(self, domain: str, record_type: str):
        """Perform DNS query."""

        try:
            answers = self.resolver.resolve(domain, record_type)

            return [str(answer) for answer in answers]

        except Exception:
            return []

    def lookup(self, url: str):
        """
        Perform DNS enumeration.

        Parameters
        ----------
        url : str

        Returns
        -------
        dict
        """

        domain = self._extract_domain(url)

        result = {
            "domain": domain,
            "A": self._query(domain, "A"),
            "AAAA": self._query(domain, "AAAA"),
            "MX": self._query(domain, "MX"),
            "NS": self._query(domain, "NS"),
            "TXT": self._query(domain, "TXT"),
            "CNAME": self._query(domain, "CNAME")
        }

        return result


dns_tool = DNSTool()


def lookup_dns(url: str):
    """
    Convenience wrapper.
    """
    return dns_tool.lookup(url)