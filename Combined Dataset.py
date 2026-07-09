"""
combine_datasets.py
===================

Combine:

1. Corrected Malicious URLs dataset
2. Tranco Top-1M trusted domains

Output:
--------
combined_dataset.csv

Columns:
--------
url
type
"""

from pathlib import Path
import pandas as pd

# ==========================================================
# CHANGE THESE PATHS
# ==========================================================

MALICIOUS_DATASET = r"C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\URL Datasets\archive (12)\corrected Malicious URLs dataset.csv"

TRUSTED_DATASET = r"C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\URL Datasets\tranco_JZK4Y-1m.csv\top-1m.csv"

OUTPUT_DATASET = r"C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\AI-Powered-Security-Operations-Platform-for-Threat-Detection-Alert-Triage-and-Incident-Investigation\combined_dataset.csv"

# ==========================================================
# LABEL MAPPING
# ==========================================================

LABEL_MAP = {
    "benign": "benign",
    "good": "benign",
    "safe": "benign",

    "phishing": "phishing",

    "malware": "malware",

    "defacement": "defacement",
}

# ==========================================================
# LOAD MALICIOUS DATASET
# ==========================================================

print("=" * 60)
print("Loading Corrected Malicious URL Dataset")
print("=" * 60)

malicious = pd.read_csv(MALICIOUS_DATASET)

required = {"url", "type"}

if not required.issubset(malicious.columns):
    raise ValueError(
        "Corrected malicious dataset must contain columns:\n"
        "url,type"
    )

malicious = malicious[["url", "type"]].copy()

malicious["url"] = (
    malicious["url"]
    .astype(str)
    .str.strip()
)

malicious["type"] = (
    malicious["type"]
    .astype(str)
    .str.lower()
    .str.strip()
    .map(LABEL_MAP)
)

malicious = malicious.dropna()

print("Loaded:", len(malicious))
print(malicious["type"].value_counts())
print()

# ==========================================================
# LOAD TRUSTED DOMAINS
# ==========================================================

print("=" * 60)
print("Loading Tranco Top Domains")
print("=" * 60)

trusted = pd.read_csv(TRUSTED_DATASET)

# First column is rank
# Second column is domain

if len(trusted.columns) < 2:
    raise ValueError("Unexpected Tranco dataset format.")

domain_column = trusted.columns[1]

trusted = trusted[[domain_column]].copy()

trusted.columns = ["url"]

trusted["url"] = (
    "https://" +
    trusted["url"]
    .astype(str)
    .str.strip()
)

trusted["type"] = "benign"

print("Loaded:", len(trusted))
print()

# ==========================================================
# MERGE
# ==========================================================

print("=" * 60)
print("Combining datasets")
print("=" * 60)

combined = pd.concat(
    [
        malicious,
        trusted
    ],
    ignore_index=True
)

combined = combined.dropna()

combined["url"] = combined["url"].astype(str).str.strip()

combined["type"] = combined["type"].astype(str).str.lower()

combined = combined.drop_duplicates(subset="url")

combined = combined.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

# ==========================================================
# SAVE
# ==========================================================

Path(OUTPUT_DATASET).parent.mkdir(
    parents=True,
    exist_ok=True
)

combined.to_csv(
    OUTPUT_DATASET,
    index=False
)

print("=" * 60)
print("Combined Dataset Created Successfully")
print("=" * 60)

print()

print("Saved to:")
print(OUTPUT_DATASET)

print()

print("Dataset Shape:")
print(combined.shape)

print()

print("Class Distribution:")
print(combined["type"].value_counts())

print()

print("Preview:")
print(combined.head())