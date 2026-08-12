"""
PHASE 1 — Authentication Dataset Preprocessing (Balanced Sample)
"""

import pandas as pd
import joblib
import os
from sklearn.preprocessing import LabelEncoder

# ---------------------------------------------------------------------------
# PATHS
# ---------------------------------------------------------------------------
AUTH_FILE    = r"C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\LANL\auth.txt"
REDTEAM_FILE = r"C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\LANL\redteam.txt"
OUTPUT_DIR   = r"C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\outputs"
ENCODER_DIR  = r"C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\encoders"
OUTPUT_CSV   = os.path.join(OUTPUT_DIR, "authentication_dataset.csv")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(ENCODER_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# COLUMNS
# ---------------------------------------------------------------------------
COLUMNS = [
    "Time", "SourceUser", "DestinationUser",
    "SourceComputer", "DestinationComputer",
    "AuthenticationType", "LogonType", "Activity", "Result",
]

CATEGORICAL_COLS = [
    "SourceUser", "DestinationUser",
    "SourceComputer", "DestinationComputer",
    "AuthenticationType", "LogonType", "Activity", "Result",
]

ADMIN_PATTERNS = ["admin", "administrator", "svc", "service", "root", "system"]
SECONDS_PER_DAY = 86400

# ---------------------------------------------------------------------------
# LOAD DATASETS
# ---------------------------------------------------------------------------
def load_auth_dataset(filepath: str) -> pd.DataFrame:
    df = pd.read_csv(filepath, names=COLUMNS, header=None, low_memory=False)
    df["Source"] = "auth"
    return df

def load_redteam_dataset(filepath: str) -> pd.DataFrame:
    df = pd.read_csv(filepath, names=["Time","SourceUser","DestinationComputer","DestinationUser"], header=None)
    df["SourceComputer"] = df["DestinationComputer"]
    df["AuthenticationType"] = "Unknown"
    df["LogonType"] = "Unknown"
    df["Activity"] = "Unknown"
    df["Result"] = "Fail"
    df = df[COLUMNS]
    df["Source"] = "redteam"
    return df

# ---------------------------------------------------------------------------
# COMBINE DATASETS (700 auth + 300 redteam)
# ---------------------------------------------------------------------------
def combine_datasets(auth_path: str, red_path: str) -> pd.DataFrame:
    df_auth = load_auth_dataset(auth_path)
    df_red  = load_redteam_dataset(red_path)

    df_auth_sampled = df_auth.sample(n=700, random_state=42)
    df_red_sampled  = df_red.sample(n=300, random_state=42)

    combined = pd.concat([df_auth_sampled, df_red_sampled], ignore_index=True)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"Combined shape: {combined.shape}")
    print(f"Auth rows: {len(df_auth_sampled)} ({len(df_auth_sampled)/len(combined)*100:.1f}%)")
    print(f"Redteam rows: {len(df_red_sampled)} ({len(df_red_sampled)/len(combined)*100:.1f}%)")
    return combined

# ---------------------------------------------------------------------------
# CLEAN DATASET
# ---------------------------------------------------------------------------
def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    df["Time"] = pd.to_numeric(df["Time"], errors="coerce")
    df.dropna(subset=["SourceUser","DestinationComputer","Time"], inplace=True)
    df.drop_duplicates(inplace=True)
    return df

# ---------------------------------------------------------------------------
# FEATURE ENGINEERING
# ---------------------------------------------------------------------------
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df["Hour"]       = (df["Time"] // 3600) % 24
    df["DayOfWeek"]  = (df["Time"] // SECONDS_PER_DAY) % 7
    df["Weekend"]    = df["DayOfWeek"].apply(lambda d: 1 if d >= 5 else 0)
    df["IsAdmin"]    = df["SourceUser"].str.lower().apply(lambda u: 1 if any(p in str(u) for p in ADMIN_PATTERNS) else 0)
    df["FailedLogin"] = df["Result"].apply(lambda r: 1 if str(r).strip().lower() in ("fail","failure","failed") else 0)
    df.sort_values(["SourceUser","Time"], inplace=True)
    df["FailedAttempts"] = df.groupby("SourceUser")["FailedLogin"].transform(lambda x: x.cumsum())
    df.sort_index(inplace=True)
    df["UserDevice"] = df["SourceUser"] + "_" + df["SourceComputer"]
    df["NewDevice"] = (~df["UserDevice"].duplicated()).astype(int)
    df.drop(columns=["UserDevice"], inplace=True)
    return df

# ---------------------------------------------------------------------------
# LABEL ENCODING
# ---------------------------------------------------------------------------
def label_encode(df: pd.DataFrame) -> pd.DataFrame:
    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col+"_enc"] = le.fit_transform(df[col].astype(str))
        encoders[col] = le
        joblib.dump(le, os.path.join(ENCODER_DIR, f"le_{col}.pkl"))
    joblib.dump(encoders, os.path.join(ENCODER_DIR, "all_encoders.pkl"))
    return df

# ---------------------------------------------------------------------------
# SAVE OUTPUT
# ---------------------------------------------------------------------------
def save_dataset(df: pd.DataFrame) -> None:
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Saved → {OUTPUT_CSV}")
    print(f"Final shape: {df.shape}")

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main() -> None:
    print("="*70)
    print(" PHASE 1 — Authentication Dataset Preprocessing")
    print("="*70)
    df = combine_datasets(AUTH_FILE, REDTEAM_FILE)
    df = clean_dataset(df)
    df = engineer_features(df)
    df = label_encode(df)
    save_dataset(df)
    print("\n✓ Phase 1 complete.")
    print("="*70)

if __name__ == "__main__":
    main()
