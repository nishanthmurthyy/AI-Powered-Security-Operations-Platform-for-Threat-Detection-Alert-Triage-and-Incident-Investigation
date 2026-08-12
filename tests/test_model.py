"""
Test loading trained XGBoost models.
"""

from pathlib import Path
import joblib

BASE = Path(__file__).resolve().parent.parent

# Current model locations
url_model = BASE / "models" / "url_xgboost_model.pkl"
auth_model = BASE / "models" / "authentication_xgboost_model.pkl"

print("=" * 60)
print("MODEL TEST")
print("=" * 60)

print("Loading URL Model...")
url = joblib.load(url_model)
print("✓ URL Model Loaded")

print("\nLoading Authentication Model...")
auth = joblib.load(auth_model)
print("✓ Authentication Model Loaded")

print("\n============================================================")
print("ALL MODELS LOADED SUCCESSFULLY")
print("============================================================")

print(f"URL Model Type            : {type(url)}")
print(f"Authentication Model Type : {type(auth)}")