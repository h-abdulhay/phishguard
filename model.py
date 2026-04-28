import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle

# dataset yuklash
data = pd.read_csv("dataset.csv")

# string ustunlarni olib tashlash
drop_cols = ["FILENAME", "URL", "Domain", "Title", "TLD"]
data = data.drop(columns=[col for col in drop_cols if col in data.columns], errors="ignore")

# X va y
X = data.drop("label", axis=1)
y = data["label"]

# NaN tozalash
X = X.fillna(0)

# train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# saqlash
pickle.dump(model, open("model.pkl", "wb"))

print("✅ Model tayyor!")
print("Train score:", model.score(X_test, y_test))

# REAL TEST
print("\nREAL TEST:")
sample = X_test.iloc[0:1]
prediction = model.predict(sample)

print("Prediction:", prediction)
print("Actual:", y_test.iloc[0])