"""
WHOIS Investigation Tool

Collects WHOIS information for URL investigations.

Information Collected:
- Registrar
- Domain Creation Date
- Expiration Date
- Updated Date
- Domain Age
- Name Servers
- Organization
- Country

Author: Sandra Jane MSc Project
"""

import whois
from datetime import datetime
from urllib.parse import urlparse


class WHOISTool:

    def __init__(self):
        pass

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""

        if url.startswith(("http://", "https://")):
            return urlparse(url).netloc

        return url

    def _parse_date(self, value):
        """
        Some WHOIS servers return lists of dates.
        """

        if isinstance(value, list):
            return value[0]

        return value

    def lookup(self, url: str):
        """
        Perform WHOIS lookup.
        """

        domain = self._extract_domain(url)

        result = {
            "domain": domain,
            "registrar": None,
            "organization": None,
            "country": None,
            "creation_date": None,
            "updated_date": None,
            "expiration_date": None,
            "domain_age_days": None,
            "name_servers": [],
            "error": None
        }

        try:

            w = whois.whois(domain)

            creation = self._parse_date(w.creation_date)
            updated = self._parse_date(w.updated_date)
            expiration = self._parse_date(w.expiration_date)

            result["registrar"] = w.registrar
            result["organization"] = getattr(w, "org", None)
            result["country"] = getattr(w, "country", None)

            if creation:
                result["creation_date"] = creation.strftime("%Y-%m-%d")
                result["domain_age_days"] = (
                    datetime.now() - creation
                ).days

            if updated:
                result["updated_date"] = updated.strftime("%Y-%m-%d")

            if expiration:
                result["expiration_date"] = expiration.strftime("%Y-%m-%d")

            nameservers = getattr(w, "name_servers", None)

            if nameservers:

                if isinstance(nameservers, list):
                    result["name_servers"] = sorted(
                        list(set(str(ns) for ns in nameservers))
                    )
                else:
                    result["name_servers"] = [str(nameservers)]

        except Exception as e:

            result["error"] = str(e)

        return result


whois_tool = WHOISTool()


def lookup_whois(url: str):
    """
    Convenience wrapper.
    """
    return whois_tool.lookup(url)