
import pickle
import shutil
from pathlib import Path

import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "phishing.csv"
MODEL_PATH = BASE_DIR / "pickle" / "model.pkl"
BACKUP_PATH = BASE_DIR / "pickle" / "model_original.pkl"

# Preserve the original model before replacing it.
if MODEL_PATH.exists() and not BACKUP_PATH.exists():
    shutil.copy2(MODEL_PATH, BACKUP_PATH)

data = pd.read_csv(DATA_PATH)

# Exclude both the row identifier and the target.
X = data.drop(columns=["Index", "class"])
y = data["class"]

if X.shape[1] != 30:
    raise ValueError(f"Expected 30 features, got {X.shape[1]}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = GradientBoostingClassifier(
    max_depth=4,
    learning_rate=0.7,
    random_state=42,
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)
print("Test accuracy:", round(accuracy_score(y_test, predictions), 4))
print(classification_report(y_test, predictions))

with MODEL_PATH.open("wb") as file:
    pickle.dump(model, file)

print(f"Compatible model saved to: {MODEL_PATH}")
print(f"Original model backup: {BACKUP_PATH}")
print("Model feature count:", model.n_features_in_)
print("Model class order:", model.classes_)
