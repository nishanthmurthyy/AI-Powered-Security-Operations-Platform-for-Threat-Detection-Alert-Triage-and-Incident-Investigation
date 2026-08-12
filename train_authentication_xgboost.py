"""
====================================================================================
AI-Powered Security Operations Platform
Authentication XGBoost Model Training

File: train_authentication_xgboost.py

Description:
    Trains an XGBoost classifier to detect malicious authentication events
    using the combined Authentication Dataset.

Author: Sandra Jane F
====================================================================================
"""

import os
import logging
import joblib
import warnings

import pandas as pd
import numpy as np

from xgboost import XGBClassifier

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
    roc_curve,
    precision_recall_curve
)

import matplotlib
matplotlib.use("Agg")      # Use non-GUI backend

import matplotlib.pyplot as plt

warnings.filterwarnings("ignore")

# ==============================================================================
# PROJECT PATHS
# ==============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_PATH = os.path.join(
    BASE_DIR,
    "outputs",
    "C:\\Users\\Administrator\\OneDrive\\Documents\\3rd sem\\project Lab\\outputs\\authentication_dataset.csv"
)

MODEL_DIR = os.path.join(BASE_DIR, "models")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ==============================================================================
# LOGGING
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)

# ==============================================================================
# LOAD DATASET
# ==============================================================================

logger.info("=" * 70)
logger.info("Loading Authentication Dataset...")

df = pd.read_csv(DATASET_PATH)

logger.info(f"Dataset Loaded Successfully")
logger.info(f"Rows    : {df.shape[0]}")
logger.info(f"Columns : {df.shape[1]}")

# ==============================================================================
# CREATE TARGET LABEL
# ==============================================================================

logger.info("Creating Binary Labels...")

df["Target"] = df["Source"].map({
    "auth": 0,
    "redteam": 1
})

if df["Target"].isnull().sum() > 0:
    raise ValueError("Unknown values detected in Source column.")

logger.info(df["Target"].value_counts())

# ==============================================================================
# FEATURE SELECTION
# ==============================================================================

FEATURE_COLUMNS = [

    "Hour",
    "DayOfWeek",
    "Weekend",
    "IsAdmin",
    "FailedLogin",
    "FailedAttempts",
    "NewDevice",

    "SourceUser_enc",
    "DestinationUser_enc",

    "SourceComputer_enc",
    "DestinationComputer_enc",

    "AuthenticationType_enc",
    "LogonType_enc",
    "Activity_enc",
    "Result_enc"

]

X = df[FEATURE_COLUMNS]

y = df["Target"]

logger.info(f"Features Selected : {len(FEATURE_COLUMNS)}")

print("\nSelected Features")
print(FEATURE_COLUMNS)

# ==============================================================================
# TRAIN TEST SPLIT
# ==============================================================================

logger.info("Splitting Dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

logger.info(f"Training Samples : {len(X_train)}")
logger.info(f"Testing Samples  : {len(X_test)}")
# ==============================================================================
# XGBOOST MODEL
# ==============================================================================

logger.info("=" * 70)
logger.info("Initializing XGBoost Classifier...")

model = XGBClassifier(

    objective="binary:logistic",
    eval_metric="logloss",

    n_estimators=200,
    max_depth=6,
    learning_rate=0.10,

    subsample=0.80,
    colsample_bytree=0.80,

    min_child_weight=2,
    gamma=0.2,

    random_state=42,
    n_jobs=-1

)

logger.info("Model Initialized Successfully")

# ==============================================================================
# TRAIN MODEL
# ==============================================================================

logger.info("=" * 70)
logger.info("Training XGBoost Model...")

model.fit(X_train, y_train)

logger.info("Training Completed Successfully")

# ==============================================================================
# PREDICTIONS
# ==============================================================================

logger.info("=" * 70)
logger.info("Generating Predictions...")

y_pred = model.predict(X_test)

y_prob = model.predict_proba(X_test)[:, 1]

logger.info("Predictions Completed")

# ==============================================================================
# MODEL EVALUATION
# ==============================================================================

logger.info("=" * 70)
logger.info("Evaluating Model Performance...")

accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_test,
    y_prob
)

print("\n" + "=" * 70)
print("AUTHENTICATION XGBOOST MODEL PERFORMANCE")
print("=" * 70)

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")
print(f"ROC-AUC   : {roc_auc:.4f}")

logger.info(f"Accuracy  : {accuracy:.4f}")
logger.info(f"Precision : {precision:.4f}")
logger.info(f"Recall    : {recall:.4f}")
logger.info(f"F1 Score  : {f1:.4f}")
logger.info(f"ROC-AUC   : {roc_auc:.4f}")

# ==============================================================================
# CLASSIFICATION REPORT
# ==============================================================================

logger.info("=" * 70)
logger.info("Classification Report")

report = classification_report(
    y_test,
    y_pred,
    target_names=[
        "Normal Authentication",
        "Malicious Authentication"
    ]
)

print("\n")
print(report)

report_path = os.path.join(
    OUTPUT_DIR,
    "Authentication_Classification_Report.txt"
)

with open(report_path, "w") as f:
    f.write(report)

logger.info(f"Classification Report Saved: {report_path}")

# ==============================================================================
# CONFUSION MATRIX
# ==============================================================================

logger.info("=" * 70)
logger.info("Generating Confusion Matrix...")

cm = confusion_matrix(
    y_test,
    y_pred
)

print("\nConfusion Matrix\n")
print(cm)

TN, FP, FN, TP = cm.ravel()

logger.info(f"True Negative : {TN}")
logger.info(f"False Positive: {FP}")
logger.info(f"False Negative: {FN}")
logger.info(f"True Positive : {TP}")

# ==============================================================================
# ROC CURVE DATA
# ==============================================================================

logger.info("=" * 70)
logger.info("Computing ROC Curve...")

fpr, tpr, roc_thresholds = roc_curve(
    y_test,
    y_prob
)

logger.info("ROC Curve Computed")

# ==============================================================================
# PRECISION-RECALL CURVE
# ==============================================================================

logger.info("=" * 70)
logger.info("Computing Precision-Recall Curve...")

precision_curve, recall_curve, pr_thresholds = precision_recall_curve(
    y_test,
    y_prob
)

logger.info("Precision-Recall Curve Computed")

print("\nTraining Phase Completed Successfully.")
# ==============================================================================
# VISUALIZATION SETTINGS
# ==============================================================================

logger.info("=" * 70)
logger.info("Generating Visualizations...")

plt.rcParams["figure.figsize"] = (8, 6)

# ==============================================================================
# CONFUSION MATRIX PLOT
# ==============================================================================

fig, ax = plt.subplots()

im = ax.imshow(cm)

ax.set_xticks([0, 1])
ax.set_yticks([0, 1])

ax.set_xticklabels(["Normal", "Malicious"])
ax.set_yticklabels(["Normal", "Malicious"])

ax.set_xlabel("Predicted Label")
ax.set_ylabel("True Label")
ax.set_title("Authentication Confusion Matrix")

for i in range(cm.shape[0]):
    for j in range(cm.shape[1]):
        ax.text(
            j,
            i,
            str(cm[i, j]),
            ha="center",
            va="center",
            fontsize=12,
            fontweight="bold"
        )

plt.tight_layout()

confusion_path = os.path.join(
    OUTPUT_DIR,
    "Authentication_Confusion_Matrix.png"
)

plt.savefig(confusion_path, dpi=300)
plt.close()

logger.info(f"Saved: {confusion_path}")

# ==============================================================================
# ROC CURVE
# ==============================================================================

plt.figure()

plt.plot(
    fpr,
    tpr,
    linewidth=2,
    label=f"ROC AUC = {roc_auc:.3f}"
)

plt.plot([0, 1], [0, 1], linestyle="--")

plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")

plt.title("Authentication ROC Curve")

plt.legend(loc="lower right")

plt.tight_layout()

roc_path = os.path.join(
    OUTPUT_DIR,
    "Authentication_ROC_Curve.png"
)

plt.savefig(roc_path, dpi=300)
plt.close()

logger.info(f"Saved: {roc_path}")

# ==============================================================================
# PRECISION-RECALL CURVE
# ==============================================================================

plt.figure()

plt.plot(
    recall_curve,
    precision_curve,
    linewidth=2
)

plt.xlabel("Recall")
plt.ylabel("Precision")

plt.title("Authentication Precision-Recall Curve")

plt.tight_layout()

pr_path = os.path.join(
    OUTPUT_DIR,
    "Authentication_PR_Curve.png"
)

plt.savefig(pr_path, dpi=300)
plt.close()

logger.info(f"Saved: {pr_path}")

# ==============================================================================
# FEATURE IMPORTANCE
# ==============================================================================

logger.info("=" * 70)
logger.info("Calculating Feature Importance...")

importance_df = pd.DataFrame({

    "Feature": FEATURE_COLUMNS,

    "Importance": model.feature_importances_

})

importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
)

print("\nFeature Importance\n")
print(importance_df)

importance_csv = os.path.join(
    OUTPUT_DIR,
    "Authentication_Feature_Importance.csv"
)

importance_df.to_csv(
    importance_csv,
    index=False
)

logger.info(f"Feature Importance CSV Saved: {importance_csv}")

# ==============================================================================
# FEATURE IMPORTANCE PLOT
# ==============================================================================

plt.figure(figsize=(10, 7))

plt.barh(
    importance_df["Feature"],
    importance_df["Importance"]
)

plt.xlabel("Importance")
plt.ylabel("Feature")

plt.title("Authentication Feature Importance")

plt.gca().invert_yaxis()

plt.tight_layout()

importance_plot = os.path.join(
    OUTPUT_DIR,
    "Authentication_Feature_Importance.png"
)

plt.savefig(
    importance_plot,
    dpi=300
)

plt.close()

logger.info(f"Saved: {importance_plot}")

# ==============================================================================
# FEATURE IMPORTANCE SUMMARY
# ==============================================================================

print("\nTop 10 Most Important Features\n")

print(
    importance_df.head(10)
)

logger.info("=" * 70)
logger.info("Visualization Generation Completed Successfully")
# ==============================================================================
# SAVE TRAINED MODEL
# ==============================================================================

logger.info("=" * 70)
logger.info("Saving Trained XGBoost Model...")

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "authentication_xgboost_model.pkl"
)

joblib.dump(model, MODEL_PATH)

logger.info(f"Model Saved Successfully -> {MODEL_PATH}")

# ==============================================================================
# SAVE FEATURE NAMES
# ==============================================================================

FEATURE_PATH = os.path.join(
    MODEL_DIR,
    "authentication_feature_names.pkl"
)

joblib.dump(FEATURE_COLUMNS, FEATURE_PATH)

logger.info(f"Feature Names Saved -> {FEATURE_PATH}")

# ==============================================================================
# SAVE LABEL INFORMATION
# ==============================================================================

LABEL_INFO = {
    0: "Normal Authentication",
    1: "Malicious Authentication"
}

LABEL_PATH = os.path.join(
    MODEL_DIR,
    "authentication_label_encoder.pkl"
)

joblib.dump(LABEL_INFO, LABEL_PATH)

logger.info(f"Label Mapping Saved -> {LABEL_PATH}")

# ==============================================================================
# SAVE TRAINING METRICS
# ==============================================================================

metrics_df = pd.DataFrame({

    "Metric": [

        "Accuracy",
        "Precision",
        "Recall",
        "F1 Score",
        "ROC AUC"

    ],

    "Value": [

        accuracy,
        precision,
        recall,
        f1,
        roc_auc

    ]

})

metrics_csv = os.path.join(
    OUTPUT_DIR,
    "Authentication_Model_Metrics.csv"
)

metrics_df.to_csv(
    metrics_csv,
    index=False
)

logger.info(f"Metrics Saved -> {metrics_csv}")

# ==============================================================================
# SAVE PREDICTIONS
# ==============================================================================

prediction_df = X_test.copy()

prediction_df["Actual"] = y_test.values
prediction_df["Prediction"] = y_pred
prediction_df["Probability"] = y_prob

prediction_csv = os.path.join(
    OUTPUT_DIR,
    "Authentication_Test_Predictions.csv"
)

prediction_df.to_csv(
    prediction_csv,
    index=False
)

logger.info(f"Predictions Saved -> {prediction_csv}")

# ==============================================================================
# TRAINING SUMMARY
# ==============================================================================

summary = f"""
=====================================================================
Authentication XGBoost Training Summary
=====================================================================

Dataset Path:
{DATASET_PATH}

Training Samples:
{len(X_train)}

Testing Samples:
{len(X_test)}

Number of Features:
{len(FEATURE_COLUMNS)}

Features Used:

"""

for feature in FEATURE_COLUMNS:
    summary += f"   • {feature}\n"

summary += f"""

=====================================================================

Accuracy  : {accuracy:.4f}
Precision : {precision:.4f}
Recall    : {recall:.4f}
F1 Score  : {f1:.4f}
ROC AUC   : {roc_auc:.4f}

=====================================================================

Confusion Matrix

{cm}

=====================================================================

Top 10 Important Features

"""

for _, row in importance_df.head(10).iterrows():
    summary += f"{row['Feature']:<35} {row['Importance']:.5f}\n"

summary += """

=====================================================================

Generated Files

authentication_xgboost_model.pkl
authentication_feature_names.pkl
authentication_label_encoder.pkl

Authentication_Model_Metrics.csv
Authentication_Test_Predictions.csv
Authentication_Classification_Report.txt

Authentication_Confusion_Matrix.png
Authentication_ROC_Curve.png
Authentication_PR_Curve.png
Authentication_Feature_Importance.csv
Authentication_Feature_Importance.png

=====================================================================
"""

summary_path = os.path.join(
    OUTPUT_DIR,
    "Authentication_Training_Summary.txt"
)

with open(summary_path, "w", encoding="utf-8") as file:
    file.write(summary)

logger.info(f"Training Summary Saved -> {summary_path}")

print(summary)

logger.info("=" * 70)
logger.info("All Model Artifacts Saved Successfully.")
# ==============================================================================
# VERIFY GENERATED FILES
# ==============================================================================

logger.info("=" * 70)
logger.info("Verifying Generated Files...")

generated_files = [

    MODEL_PATH,
    FEATURE_PATH,
    LABEL_PATH,

    metrics_csv,
    prediction_csv,
    report_path,
    summary_path,

    confusion_path,
    roc_path,
    pr_path,
    importance_csv,
    importance_plot

]

print("\n")
print("=" * 70)
print("GENERATED FILES")
print("=" * 70)

for file in generated_files:

    if os.path.exists(file):
        print(f"✓ {os.path.basename(file)}")
    else:
        print(f"✗ Missing : {os.path.basename(file)}")

logger.info("Verification Completed")

# ==============================================================================
# FINAL SUMMARY
# ==============================================================================

print("\n")
print("=" * 70)
print("AUTHENTICATION XGBOOST TRAINING COMPLETED")
print("=" * 70)

print(f"Dataset Used          : {DATASET_PATH}")
print(f"Training Samples      : {len(X_train)}")
print(f"Testing Samples       : {len(X_test)}")
print(f"Features Used         : {len(FEATURE_COLUMNS)}")

print("\nPerformance")

print(f"Accuracy              : {accuracy:.4f}")
print(f"Precision             : {precision:.4f}")
print(f"Recall                : {recall:.4f}")
print(f"F1 Score              : {f1:.4f}")
print(f"ROC AUC               : {roc_auc:.4f}")

print("\nModel Saved To")
print(MODEL_PATH)

print("\nTraining Summary")
print(summary_path)

print("=" * 70)
print("READY FOR DEPLOYMENT")
print("=" * 70)

logger.info("Authentication XGBoost Pipeline Completed Successfully.")

# ==============================================================================
# MAIN
# ==============================================================================

def main():
    """
    Authentication Model Training Entry Point.
    The training pipeline executes sequentially when the script is run.
    """
    pass


if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        logger.warning("Training Interrupted by User.")

    except Exception as e:

        logger.exception("Training Failed.")
        print(f"\nERROR: {e}")

    finally:

        logger.info("Program Finished.")