import joblib
import os

path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "url_xgboost_model.pkl"
)

print("Exists:", os.path.exists(path))

model = joblib.load(path)

print(type(model))
print("Feature names:", model.feature_names_in_)
print("Loaded successfully!")