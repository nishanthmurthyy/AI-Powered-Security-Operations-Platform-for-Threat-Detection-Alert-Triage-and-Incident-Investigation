import pandas as pd

# Load the processed dataset
df = pd.read_csv(r"C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\outputs\authentication_dataset.csv")

# Count rows by Source
counts = df["Source"].value_counts()
print("\nSource counts:")
print(counts)

# Calculate percentages
percentages = counts / len(df) * 100
print("\nSource percentages:")
print(percentages.round(2))
