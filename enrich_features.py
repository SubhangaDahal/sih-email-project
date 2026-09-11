# export_model.py
from pathlib import Path
import pandas as pd
from xgboost import XGBClassifier

df = pd.read_csv("dataset/phishing_emails_features.csv")
features = [
    "urgency_score",
    "financial_request_score",
    "authority_impersonation_score",
    "grammar_anomaly_score",
]

X = df[features]
y = df["label"].astype(int)

model = XGBClassifier(
    n_estimators=60,
    max_depth=3,
    learning_rate=0.08,
    eval_metric="logloss",
    random_state=42,
)
model.fit(X, y)

save_dir = Path("models")
save_dir.mkdir(exist_ok=True)
model.save_model(save_dir / "threat_model.json")
print("[+] Clean semantic model exported to models/threat_model.json")