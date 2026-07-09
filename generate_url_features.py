"""
generate_url_features.py
========================

Generate the 32-feature URL dataset required by the CyberShield URL XGBoost model.

Input CSV:
    url,type

Supported type values:
    benign
    defacement
    phishing
    malware

Output:
    url_features.csv
"""

from pathlib import Path
import math
import re
import urllib.parse

import pandas as pd


# ==========================================================
# PATHS
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent

INPUT_CSV = Path(
    r"C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\AI-Powered-Security-Operations-Platform-for-Threat-Detection-Alert-Triage-and-Incident-Investigation\combined_dataset.csv"
)
OUTPUT_CSV = BASE_DIR / "url_features.csv"


# ==========================================================
# FEATURE DEFINITIONS
# ==========================================================

URL_FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_digits",
    "num_special_chars",
    "has_https",
    "has_ip_address",
    "has_at_symbol",
    "has_double_slash",
    "has_suspicious_tld",
    "subdomain_depth",
    "path_depth",
    "has_port",
    "has_query_params",
    "num_query_params",
    "has_fragment",
    "url_entropy",
    "ssl_valid",
    "ssl_days_remaining",
    "domain_age_days",
    "is_new_domain",
    "missing_hsts",
    "missing_csp",
    "missing_xframe",
    "missing_xcontent",
    "missing_referrer",
    "has_open_redirect",
    "phishing_keywords",
    "suspicious_pattern_score",
    "redirect_count",
]

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc",
    ".top", ".club", ".work", ".party", ".date", ".faith",
    ".review", ".stream", ".download", ".link", ".click",
    ".zip", ".mov", ".cam",
}

PHISHING_KEYWORDS = [
    "login", "signin", "account", "update", "verify", "secure",
    "bank", "paypal", "ebay", "amazon", "netflix", "apple",
    "password", "confirm", "suspend", "unlock", "recover",
    "wallet", "crypto", "urgent", "limited", "free", "prize",
    "office365", "microsoft", "outlook", "onedrive", "dropbox",
    "invoice", "payment", "gift", "bonus",
]

SUSPICIOUS_PATTERNS = [
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"--[a-z]",
    r"[a-z]@[a-z]",
    r"paypal.*\.(?!com)",
    r"(?:secure|login|account).*-[a-z]+\.",
]

LABEL_MAP = {
    "benign": "Low Risk",
    "defacement": "Medium Risk",
    "phishing": "High Risk",
    "malware": "High Risk",
}


# ==========================================================
# HELPERS
# ==========================================================

def normalize_url(raw_url: str) -> str:
    """
    Ensure urlparse sees the domain as netloc.

    Without this, urlparse("youtube.com/watch") treats youtube.com
    as path, causing domain_length = 0 and corrupt training data.
    """
    url = str(raw_url).strip()

    if not url or url.lower() in {"nan", "none", "null"}:
        raise ValueError("Empty URL")

    url = url.replace("\\", "/")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    return url


def get_registered_domain_parts(hostname: str) -> list[str]:
    hostname = hostname.lower().strip(".")
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return [part for part in hostname.split(".") if part]


def calculate_entropy(value: str) -> float:
    if not value:
        return 0.0

    freq = {
        char: value.count(char) / len(value)
        for char in set(value)
    }

    return -sum(
        probability * math.log2(probability)
        for probability in freq.values()
        if probability > 0
    )


def extract_url_features(raw_url: str) -> dict:
    url = normalize_url(raw_url)

    parsed = urllib.parse.urlparse(url)

    domain = parsed.netloc.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    if "@" in domain:
        domain = domain.split("@")[-1]

    hostname = domain.split(":")[0].strip().lower()

    if not hostname:
        raise ValueError(f"Could not parse hostname from URL: {raw_url}")

    domain_parts = get_registered_domain_parts(hostname)

    feat = {}

    feat["url_length"] = len(url)
    feat["domain_length"] = len(hostname)
    feat["num_dots"] = url.count(".")
    feat["num_hyphens"] = url.count("-")
    feat["num_underscores"] = url.count("_")
    feat["num_digits"] = sum(char.isdigit() for char in url)
    feat["num_special_chars"] = sum(char in "@#!%&*=<>|" for char in url)

    feat["has_https"] = int(parsed.scheme.lower() == "https")

    feat["has_ip_address"] = int(
        re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) is not None
    )

    feat["has_at_symbol"] = int("@" in url)

    feat["has_double_slash"] = int("//" in path)

    feat["has_suspicious_tld"] = int(
        any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
    )

    feat["subdomain_depth"] = max(0, len(domain_parts) - 2)

    feat["path_depth"] = len([part for part in path.split("/") if part])

    feat["has_port"] = int(":" in domain)

    feat["has_query_params"] = int(bool(query))

    feat["num_query_params"] = len(
        urllib.parse.parse_qs(query)
    )

    feat["has_fragment"] = int(bool(fragment))

    feat["url_entropy"] = calculate_entropy(url)

    # ======================================================
    # Training-time live-check features
    # ======================================================
    # Keep these defaults consistent with dashboard prediction.
    # Do NOT mix real live values here unless you collect them
    # for every training URL in the same way.
    # ======================================================

    feat["ssl_valid"] = 0
    feat["ssl_days_remaining"] = 0

    feat["domain_age_days"] = 365
    feat["is_new_domain"] = 0

    feat["missing_hsts"] = 1
    feat["missing_csp"] = 1
    feat["missing_xframe"] = 1
    feat["missing_xcontent"] = 1
    feat["missing_referrer"] = 1

    feat["has_open_redirect"] = int(
        re.search(
            r"(redirect|url|return|next|goto)=https?://",
            url,
            re.I,
        )
        is not None
    )

    lowered_url = url.lower()

    feat["phishing_keywords"] = sum(
        keyword in lowered_url
        for keyword in PHISHING_KEYWORDS
    )

    pattern_hits = sum(
        1
        for pattern in SUSPICIOUS_PATTERNS
        if re.search(pattern, lowered_url, re.I)
    )

    feat["suspicious_pattern_score"] = pattern_hits / len(SUSPICIOUS_PATTERNS)

    feat["redirect_count"] = 0

    return feat


# ==========================================================
# MAIN
# ==========================================================

def main() -> None:
    if not INPUT_CSV.exists():
        raise FileNotFoundError(
            f"Input dataset not found: {INPUT_CSV}\n"
            "Place malicious_phish.csv in the same folder as this script."
        )

    print("=" * 60)
    print("Loading Raw URL Dataset")
    print("=" * 60)

    df = pd.read_csv(INPUT_CSV)

    required_columns = {"url", "type"}
    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"Input CSV missing required columns: {sorted(missing_columns)}"
        )

    df = df.dropna(subset=["url", "type"]).copy()
    df["type"] = df["type"].astype(str).str.lower().str.strip()
    df["IncidentGrade"] = df["type"].map(LABEL_MAP)

    unknown_labels = sorted(
        set(df.loc[df["IncidentGrade"].isna(), "type"].unique())
    )

    if unknown_labels:
        raise ValueError(
            f"Unsupported type values found: {unknown_labels}\n"
            f"Supported values: {sorted(LABEL_MAP)}"
        )

    print("\nRaw Class Distribution")
    print(df["type"].value_counts())

    rows = []
    failed = 0
    total = len(df)

    for index, row in df.iterrows():
        try:
            features = extract_url_features(row["url"])
            features["IncidentGrade"] = row["IncidentGrade"]
            rows.append(features)
        except Exception:
            failed += 1

        if (len(rows) + failed) % 10000 == 0:
            print(f"Processed {len(rows) + failed}/{total}")

    feature_df = pd.DataFrame(rows)

    if feature_df.empty:
        raise ValueError("No valid URL feature rows were generated.")

    feature_df = feature_df[URL_FEATURE_NAMES + ["IncidentGrade"]]

    # Remove impossible parser failures. A real URL row should have a domain.
    before = len(feature_df)
    feature_df = feature_df[feature_df["domain_length"] > 0].copy()
    removed_domain_failures = before - len(feature_df)

    feature_df.to_csv(
        OUTPUT_CSV,
        index=False,
    )

    print("\n" + "=" * 60)
    print("Feature Generation Complete")
    print("=" * 60)

    print("Saved to:", OUTPUT_CSV)
    print("Shape:", feature_df.shape)
    print("Failed rows:", failed)
    print("Removed domain parse failures:", removed_domain_failures)

    print("\nGenerated Class Distribution")
    print(feature_df["IncidentGrade"].value_counts())

    print("\nDomain Length Diagnostics")
    print(feature_df["domain_length"].describe())

    print("\nHTTPS Distribution")
    print(feature_df["has_https"].value_counts())

    print("\nPreview")
    print(feature_df.head())


if __name__ == "__main__":
    main()