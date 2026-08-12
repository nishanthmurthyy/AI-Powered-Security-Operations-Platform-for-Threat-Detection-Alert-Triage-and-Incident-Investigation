"""
=============================================================================
PHASE 2 — Authentication Feature Analysis
=============================================================================
Project : AI-Powered Security Operations Platform
Module  : Authentication Monitoring — Exploratory Data Analysis

What this file does
-------------------
1.  Dataset statistics & shape summary
2.  Missing value analysis
3.  Feature distributions (numeric)
4.  Authentication type distribution
5.  Login result distribution
6.  User activity distribution
7.  Hour-of-day attack pattern heatmap
8.  Correlation heatmap (numeric features)
9.  Failed login analysis per user (top offenders)
10. Off-hours vs business-hours breakdown
11. Saves all plots to outputs/plots/

Run AFTER authentication_preprocessing.py has produced authentication_dataset.csv
=============================================================================
"""

import os
import warnings

import matplotlib
matplotlib.use("Agg")   # non-interactive backend for server environments
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# PATHS
# ---------------------------------------------------------------------------
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
PLOT_DIR   = os.path.join(OUTPUT_DIR, "plots")
DATA_CSV   = r"C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\outputs\authentication_dataset.csv"

os.makedirs(PLOT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# STYLE
# ---------------------------------------------------------------------------
PALETTE   = "plasma"
BG_COLOR  = "#0d1117"
TEXT_COLOR = "#e4e8f0"
GRID_COLOR = "#1f2937"
ACCENT    = "#3b82f6"
RED_ACCENT = "#ef4444"
GREEN_ACCENT = "#22d89a"

plt.rcParams.update({
    "figure.facecolor":  BG_COLOR,
    "axes.facecolor":    "#111827",
    "axes.edgecolor":    GRID_COLOR,
    "axes.labelcolor":   TEXT_COLOR,
    "axes.titlecolor":   TEXT_COLOR,
    "xtick.color":       TEXT_COLOR,
    "ytick.color":       TEXT_COLOR,
    "text.color":        TEXT_COLOR,
    "grid.color":        GRID_COLOR,
    "grid.alpha":        0.4,
    "legend.facecolor":  "#161d2e",
    "legend.edgecolor":  GRID_COLOR,
    "font.family":       "sans-serif",
    "font.size":         11,
})


def _save(fig: plt.Figure, name: str) -> None:
    path = os.path.join(PLOT_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG_COLOR)
    plt.close(fig)
    print(f"  Saved → {path}")


# ---------------------------------------------------------------------------
# LOAD DATA
# ---------------------------------------------------------------------------

def load_data() -> pd.DataFrame:
    print(f"\n[LOAD] Reading {DATA_CSV} ...")
    df = pd.read_csv(DATA_CSV, low_memory=False)
    print(f"  Shape: {df.shape}")
    return df


# ---------------------------------------------------------------------------
# ANALYSIS 1 — Dataset Statistics
# ---------------------------------------------------------------------------

def analyse_statistics(df: pd.DataFrame) -> None:
    print("\n[1] Dataset Statistics")
    print("-" * 50)
    print(f"  Rows              : {len(df):,}")
    print(f"  Columns           : {df.shape[1]}")
    print(f"  Memory usage      : {df.memory_usage(deep=True).sum() / 1e6:.2f} MB")
    print(f"\n  Dtypes:\n{df.dtypes.to_string()}")
    print(f"\n  Numeric summary:\n{df.describe(include='number').to_string()}")


# ---------------------------------------------------------------------------
# ANALYSIS 2 — Missing Value Heatmap
# ---------------------------------------------------------------------------

def analyse_missing(df: pd.DataFrame) -> None:
    print("\n[2] Missing Value Analysis")
    missing = df.isnull().sum()
    missing = missing[missing > 0]
    if missing.empty:
        print("  No missing values detected.")
        return

    fig, ax = plt.subplots(figsize=(10, max(4, len(missing) * 0.4)))
    colors = [RED_ACCENT if v > len(df)*0.1 else ACCENT for v in missing.values]
    ax.barh(missing.index, missing.values, color=colors)
    ax.set_title("Missing Values per Column", fontsize=14, fontweight="bold")
    ax.set_xlabel("Count")
    ax.grid(axis="x", alpha=0.3)
    _save(fig, "01_missing_values.png")


# ---------------------------------------------------------------------------
# ANALYSIS 3 — Numeric Feature Distributions
# ---------------------------------------------------------------------------

def analyse_distributions(df: pd.DataFrame) -> None:
    print("\n[3] Numeric Feature Distributions")
    num_cols = [
        c for c in ["Hour", "DayOfWeek", "FailedAttempts", "FailedLogin",
                    "IsAdmin", "NewDevice", "Weekend", "OffHours"]
        if c in df.columns
    ]
    if not num_cols:
        print("  No numeric feature columns found.")
        return

    n    = len(num_cols)
    cols = 3
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(cols * 5, rows * 4))
    axes = axes.flatten()

    for i, col in enumerate(num_cols):
        ax = axes[i]
        ax.hist(df[col].dropna(), bins=30, color=ACCENT, edgecolor="#1f2937", alpha=0.85)
        ax.set_title(col, fontsize=12, fontweight="bold")
        ax.set_xlabel("Value");  ax.set_ylabel("Count")
        ax.grid(axis="y", alpha=0.3)

    for j in range(i + 1, len(axes)):
        axes[j].set_visible(False)

    fig.suptitle("Feature Distributions", fontsize=16, fontweight="bold", y=1.01)
    fig.tight_layout()
    _save(fig, "02_feature_distributions.png")


# ---------------------------------------------------------------------------
# ANALYSIS 4 — Correlation Heatmap
# ---------------------------------------------------------------------------

def analyse_correlation(df: pd.DataFrame) -> None:
    print("\n[4] Correlation Heatmap")
    num_df = df.select_dtypes(include="number").drop(
        columns=["Time"], errors="ignore"
    )
    if num_df.shape[1] < 2:
        print("  Not enough numeric columns for correlation.");  return

    corr = num_df.corr()
    fig, ax = plt.subplots(figsize=(max(8, len(corr) * 0.8), max(6, len(corr) * 0.7)))
    mask = np.triu(np.ones_like(corr, dtype=bool))
    sns.heatmap(
        corr, mask=mask, annot=True, fmt=".2f", cmap="RdYlGn",
        center=0, vmin=-1, vmax=1, linewidths=0.5,
        linecolor=GRID_COLOR, ax=ax,
        annot_kws={"size": 8},
        cbar_kws={"shrink": 0.8},
    )
    ax.set_title("Feature Correlation Heatmap", fontsize=14, fontweight="bold")
    fig.tight_layout()
    _save(fig, "03_correlation_heatmap.png")


# ---------------------------------------------------------------------------
# ANALYSIS 5 — Authentication Type Distribution
# ---------------------------------------------------------------------------

def analyse_auth_type(df: pd.DataFrame) -> None:
    print("\n[5] Authentication Type Distribution")
    col = "AuthenticationType"
    if col not in df.columns:
        print("  Column not found.");  return

    counts = df[col].value_counts().head(15)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # Bar chart
    colors = [ACCENT if i == 0 else "#6b7280" for i in range(len(counts))]
    ax1.bar(counts.index, counts.values, color=colors, edgecolor=GRID_COLOR)
    ax1.set_title("Authentication Types (Bar)", fontsize=12, fontweight="bold")
    ax1.set_xlabel("Auth Type");  ax1.set_ylabel("Count")
    ax1.tick_params(axis="x", rotation=30)
    ax1.grid(axis="y", alpha=0.3)

    # Pie chart
    wedge_colors = sns.color_palette(PALETTE, len(counts))
    ax2.pie(
        counts.values, labels=counts.index,
        autopct="%1.1f%%", colors=wedge_colors,
        textprops={"color": TEXT_COLOR},
        wedgeprops={"edgecolor": BG_COLOR, "linewidth": 1.5},
    )
    ax2.set_title("Authentication Types (Share)", fontsize=12, fontweight="bold")

    fig.suptitle("Authentication Type Analysis", fontsize=14, fontweight="bold")
    fig.tight_layout()
    _save(fig, "04_auth_type_distribution.png")


# ---------------------------------------------------------------------------
# ANALYSIS 6 — Login Result Distribution
# ---------------------------------------------------------------------------

def analyse_results(df: pd.DataFrame) -> None:
    print("\n[6] Login Result Distribution")
    col = "Result"
    if col not in df.columns:
        print("  Column not found.");  return

    counts  = df[col].value_counts()
    success = counts.get("Success", 0)
    fail    = counts.get("Fail", counts.get("Failure", 0))
    total   = len(df)

    print(f"  Success : {success:,}  ({success/total*100:.1f}%)")
    print(f"  Fail    : {fail:,}   ({fail/total*100:.1f}%)")

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    clrs = [GREEN_ACCENT if v == "Success" else RED_ACCENT for v in counts.index]
    axes[0].bar(counts.index, counts.values, color=clrs, edgecolor=GRID_COLOR, width=0.5)
    axes[0].set_title("Login Results", fontsize=12, fontweight="bold")
    axes[0].set_ylabel("Count"); axes[0].grid(axis="y", alpha=0.3)

    axes[1].pie(
        counts.values, labels=counts.index, colors=clrs,
        autopct="%1.1f%%",
        textprops={"color": TEXT_COLOR},
        wedgeprops={"edgecolor": BG_COLOR, "linewidth": 1.5},
    )
    axes[1].set_title("Login Result Share", fontsize=12, fontweight="bold")

    fig.suptitle("Login Result Analysis", fontsize=14, fontweight="bold")
    fig.tight_layout()
    _save(fig, "05_login_result_distribution.png")


# ---------------------------------------------------------------------------
# ANALYSIS 7 — User Activity Distribution (Top 20)
# ---------------------------------------------------------------------------

def analyse_user_activity(df: pd.DataFrame) -> None:
    print("\n[7] User Activity Distribution")
    col = "SourceUser"
    if col not in df.columns:
        print("  Column not found.");  return

    top_users = df[col].value_counts().head(20)
    fig, ax   = plt.subplots(figsize=(12, 6))
    palette   = sns.color_palette(PALETTE, len(top_users))

    bars = ax.barh(top_users.index[::-1], top_users.values[::-1],
                   color=palette[::-1], edgecolor=GRID_COLOR)

    for bar, val in zip(bars, top_users.values[::-1]):
        ax.text(bar.get_width() + max(top_users.values) * 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{val:,}", va="center", fontsize=9)

    ax.set_title("Top 20 Most Active Users", fontsize=14, fontweight="bold")
    ax.set_xlabel("Number of Authentication Events")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    _save(fig, "06_user_activity_distribution.png")


# ---------------------------------------------------------------------------
# ANALYSIS 8 — Hourly Attack Pattern Heatmap
# ---------------------------------------------------------------------------

def analyse_hourly_heatmap(df: pd.DataFrame) -> None:
    print("\n[8] Hourly Attack Pattern Heatmap")
    if "Hour" not in df.columns or "FailedLogin" not in df.columns:
        print("  Required columns missing.");  return

    pivot = (
        df.groupby(["DayOfWeek", "Hour"])["FailedLogin"]
        .sum()
        .unstack(fill_value=0)
    )
    day_labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    pivot.index = [day_labels[i] for i in pivot.index if i < 7]

    fig, ax = plt.subplots(figsize=(18, 5))
    sns.heatmap(
        pivot, cmap="YlOrRd", ax=ax,
        linewidths=0.3, linecolor=GRID_COLOR,
        cbar_kws={"label": "Failed Logins", "shrink": 0.8},
    )
    ax.set_title("Failed Login Heatmap — Day of Week vs Hour", fontsize=14, fontweight="bold")
    ax.set_xlabel("Hour of Day"); ax.set_ylabel("Day of Week")
    fig.tight_layout()
    _save(fig, "07_hourly_attack_heatmap.png")


# ---------------------------------------------------------------------------
# ANALYSIS 9 — Top Failed Login Users
# ---------------------------------------------------------------------------

def analyse_failed_users(df: pd.DataFrame) -> None:
    print("\n[9] Top Failed Login Users")
    if "FailedLogin" not in df.columns or "SourceUser" not in df.columns:
        print("  Required columns missing.");  return

    failed = (
        df[df["FailedLogin"] == 1]
        .groupby("SourceUser")
        .size()
        .sort_values(ascending=False)
        .head(15)
    )
    if failed.empty:
        print("  No failed logins found.");  return

    fig, ax = plt.subplots(figsize=(10, 6))
    palette = sns.color_palette("Reds_r", len(failed))
    ax.barh(failed.index[::-1], failed.values[::-1], color=palette, edgecolor=GRID_COLOR)
    ax.set_title("Top 15 Users by Failed Login Count", fontsize=14, fontweight="bold")
    ax.set_xlabel("Failed Login Events")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    _save(fig, "08_failed_login_users.png")


# ---------------------------------------------------------------------------
# ANALYSIS 10 — Off-Hours vs Business Hours
# ---------------------------------------------------------------------------

def analyse_off_hours(df: pd.DataFrame) -> None:
    print("\n[10] Off-Hours vs Business Hours")
    if "OffHours" not in df.columns:
        print("  OffHours column not found.");  return

    counts  = df["OffHours"].value_counts().rename({0: "Business Hours", 1: "Off-Hours"})
    fig, ax = plt.subplots(figsize=(7, 5))
    clrs    = [GREEN_ACCENT, RED_ACCENT]
    ax.bar(counts.index, counts.values, color=clrs, edgecolor=GRID_COLOR, width=0.5)
    ax.set_title("Login Timing: Business vs Off-Hours", fontsize=13, fontweight="bold")
    ax.set_ylabel("Events"); ax.grid(axis="y", alpha=0.3)
    for i, (label, val) in enumerate(counts.items()):
        ax.text(i, val + len(df) * 0.005, f"{val:,}\n({val/len(df)*100:.1f}%)",
                ha="center", fontsize=10)
    fig.tight_layout()
    _save(fig, "09_off_hours_analysis.png")


# ---------------------------------------------------------------------------
# ANALYSIS 11 — Source Distribution
# ---------------------------------------------------------------------------

def analyse_source_split(df: pd.DataFrame) -> None:
    print("\n[11] Auth vs Redteam Source Split")
    if "Source" not in df.columns:
        print("  Source column not found.");  return

    counts = df["Source"].value_counts()
    fig, ax = plt.subplots(figsize=(7, 5))
    clrs = [GREEN_ACCENT, RED_ACCENT][:len(counts)]
    ax.bar(counts.index, counts.values, color=clrs, edgecolor=GRID_COLOR, width=0.45)
    ax.set_title("Dataset Source Distribution", fontsize=13, fontweight="bold")
    ax.set_ylabel("Records"); ax.grid(axis="y", alpha=0.3)
    for i, (label, val) in enumerate(counts.items()):
        ax.text(i, val + len(df)*0.005, f"{val:,}\n({val/len(df)*100:.1f}%)",
                ha="center", fontsize=10)
    fig.tight_layout()
    _save(fig, "10_source_distribution.png")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 70)
    print(" PHASE 2 — Authentication Feature Analysis")
    print("=" * 70)

    df = load_data()

    analyse_statistics(df)
    analyse_missing(df)
    analyse_distributions(df)
    analyse_correlation(df)
    analyse_auth_type(df)
    analyse_results(df)
    analyse_user_activity(df)
    analyse_hourly_heatmap(df)
    analyse_failed_users(df)
    analyse_off_hours(df)
    analyse_source_split(df)

    print(f"\n✓ Phase 2 complete. All plots saved → {PLOT_DIR}")
    print("=" * 70)


if __name__ == "__main__":
    main()