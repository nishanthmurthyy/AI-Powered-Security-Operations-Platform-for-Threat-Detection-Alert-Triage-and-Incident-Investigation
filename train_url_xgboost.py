"""
train_url_xgboost.py
====================

Train the CyberShield URL Risk Detection Model

Input:
    url_features_balanced.csv

Output:
    url_xgboost_model.pkl
    url_label_encoder.pkl
    classification_report.txt
    feature_importance.csv
    confusion_matrix.png
    feature_importance.png
"""

from pathlib import Path
import joblib
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib
matplotlib.use("Agg")

from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

from xgboost import XGBClassifier

# ==========================================================
# PATHS
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent

INPUT_CSV = BASE_DIR / r"C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\AI-Powered-Security-Operations-Platform-for-Threat-Detection-Alert-Triage-and-Incident-Investigation\url_features_balanced.csv"

MODEL_PATH = BASE_DIR / "url_xgboost_model.pkl"

ENCODER_PATH = BASE_DIR / "url_label_encoder.pkl"

FEATURE_IMPORTANCE_CSV = BASE_DIR / "feature_importance.csv"

CONFUSION_MATRIX_PNG = BASE_DIR / "confusion_matrix.png"

FEATURE_IMPORTANCE_PNG = BASE_DIR / "feature_importance.png"

REPORT_TXT = BASE_DIR / "classification_report.txt"

# ==========================================================
# LOAD DATASET
# ==========================================================

print("=" * 60)
print("Loading Dataset")
print("=" * 60)

df = pd.read_csv(INPUT_CSV)

print(df.head())

print()

print(df["IncidentGrade"].value_counts())

# ==========================================================
# FEATURES / LABELS
# ==========================================================

X = df.drop(columns=["IncidentGrade"])

y = df["IncidentGrade"]

# ==========================================================
# ENCODE LABELS
# ==========================================================

encoder = LabelEncoder()

y_encoded = encoder.fit_transform(y)

print()

print("Label Mapping:")

for cls, enc in zip(encoder.classes_, encoder.transform(encoder.classes_)):
    print(f"{cls:<15} -> {enc}")

# ==========================================================
# TRAIN TEST SPLIT
# ==========================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.20,
    random_state=42,
    stratify=y_encoded,
)

print()

print("Training samples :", len(X_train))
print("Testing samples  :", len(X_test))

# ==========================================================
# XGBOOST MODEL
# ==========================================================

model = XGBClassifier(
    objective="multi:softprob",
    num_class=len(encoder.classes_),

    n_estimators=300,
    max_depth=8,
    learning_rate=0.05,

    subsample=0.8,
    colsample_bytree=0.8,

    eval_metric="mlogloss",

    random_state=42,
)

print()

print("Training XGBoost...")

model.fit(X_train, y_train)

print("Training Complete.")

# ==========================================================
# PREDICTION
# ==========================================================

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print()

print("=" * 60)
print("Accuracy")
print("=" * 60)

print(f"{accuracy*100:.2f}%")

# ==========================================================
# CLASSIFICATION REPORT
# ==========================================================

report = classification_report(
    y_test,
    predictions,
    target_names=encoder.classes_,
)

print()

print(report)

with open(REPORT_TXT, "w") as f:
    f.write(report)

# ==========================================================
# CONFUSION MATRIX
# ==========================================================

cm = confusion_matrix(y_test, predictions)

plt.figure(figsize=(7,6))

sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues",
    xticklabels=encoder.classes_,
    yticklabels=encoder.classes_,
)

plt.xlabel("Predicted")

plt.ylabel("Actual")

plt.title("Confusion Matrix")

plt.tight_layout()

plt.savefig(CONFUSION_MATRIX_PNG)

plt.close()

# ==========================================================
# FEATURE IMPORTANCE
# ==========================================================

importance = pd.DataFrame({

    "Feature": X.columns,

    "Importance": model.feature_importances_

})

importance = importance.sort_values(
    "Importance",
    ascending=False,
)

importance.to_csv(
    FEATURE_IMPORTANCE_CSV,
    index=False,
)

plt.figure(figsize=(10,10))

sns.barplot(
    data=importance.head(20),
    x="Importance",
    y="Feature",
)

plt.title("Top 20 Feature Importance")

plt.tight_layout()

plt.savefig(FEATURE_IMPORTANCE_PNG)

plt.close()

# ==========================================================
# SAVE MODEL
# ==========================================================

joblib.dump(model, MODEL_PATH)

joblib.dump(encoder, ENCODER_PATH)

print()

print("=" * 60)
print("Training Finished Successfully")
print("=" * 60)

print()

print("Model Saved:")
print(MODEL_PATH)

print()

print("Label Encoder Saved:")
print(ENCODER_PATH)

print()

print("Feature Importance CSV:")
print(FEATURE_IMPORTANCE_CSV)

print()

print("Classification Report:")
print(REPORT_TXT)

print()

print("Confusion Matrix:")
print(CONFUSION_MATRIX_PNG)

print()

print("Feature Importance Plot:")
print(FEATURE_IMPORTANCE_PNG)

print()

print("Top 10 Features")

print(importance.head(10))