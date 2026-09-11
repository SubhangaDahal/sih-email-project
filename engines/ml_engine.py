from pathlib import Path
import numpy as np
import xgboost as xgb


class PhishingXGBPredictor:
    """Loads the exported JSON artifact and evaluates semantic threat probabilities."""

    def __init__(self, model_path: Path | str = "../models/threat_model.json"):
        self.model_path = Path(model_path)
        if not self.model_path.is_file():
            raise FileNotFoundError(f"Model artifact not found at {self.model_path}")

        self.model = xgb.XGBClassifier()
        self.model.load_model(str(self.model_path))

    def predict_threat_score(
        self,
        urgency: float,
        financial: float,
        authority: float,
        grammar: float,
    ) -> float:
        # Pass the 4 LLM semantic scores as a 2D float32 array
        features = np.array(
            [[urgency, financial, authority, grammar]],
            dtype=np.float32,
        )
        # Predict probability of class 1 (phishing)
        return float(self.model.predict_proba(features)[0][1])