import pandas as pd

df = pd.read_csv(r"C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\AI-Powered-Security-Operations-Platform-for-Threat-Detection-Alert-Triage-and-Incident-Investigation\url_features.csv")

low = df[df["IncidentGrade"] == "Low Risk"].sample(
    n=120000,
    random_state=42
)

medium = df[df["IncidentGrade"] == "Medium Risk"]

high = df[df["IncidentGrade"] == "High Risk"]

balanced = pd.concat([low, medium, high])

balanced = balanced.sample(frac=1, random_state=42)

balanced.to_csv("url_features_balanced.csv", index=False)

print(balanced["IncidentGrade"].value_counts())