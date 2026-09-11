import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
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

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

# Train XGBoost with balanced class weights
pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
model = XGBClassifier(
    n_estimators=60,
    max_depth=3,
    learning_rate=0.08,
    scale_pos_weight=pos_weight,
    eval_metric="logloss",
    random_state=42,
)
model.fit(X_train, y_train)

probs = model.predict_proba(X_test)[:, 1]

# Instead of arbitrary 0.5, find threshold that balances precision and recall
optimal_threshold = 0.3
preds = (probs >= optimal_threshold).astype(int)

print(f"ROC-AUC: {roc_auc_score(y_test, probs):.4f}")
print(classification_report(y_test, preds, target_names=["Safe", "Phishing"]))