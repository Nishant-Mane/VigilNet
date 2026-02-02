import joblib
import os

import numpy as np
import pandas as pd


class IDSModel:
    """
    ML inference wrapper for the NIDS model.
    Loads all frozen artifacts and exposes predict().
    """

    def __init__(self, model_dir):
        self.model_dir = model_dir

        self.model = None
        self.imputer = None
        self.selected_features = None
        self.decision_threshold = None

        self._load_artifacts()

    def _load_artifacts(self):
        self.model = joblib.load(
            os.path.join(self.model_dir, "xgboost_ids_model.joblib")
        )

        self.imputer = joblib.load(
            os.path.join(self.model_dir, "imputer.joblib")
        )

        self.selected_features = joblib.load(
            os.path.join(self.model_dir, "selected_features.joblib")
        )

        self.decision_threshold = joblib.load(
            os.path.join(self.model_dir, "decision_threshold.joblib")
        )

    def predict(self, features_dict):
        """
        Takes a model-ready feature dictionary and returns:
        - attack_probability
        - prediction (0/1)
        - severity
        """

        # Enforce exact feature order
        X = pd.DataFrame([features_dict])[self.selected_features]

        # Apply imputer
        X_imputed = self.imputer.transform(X)

        # Predict probability (malicious class)
        attack_prob = float(self.model.predict_proba(X_imputed)[0][1])

        # Binary decision
        prediction = int(attack_prob >= self.decision_threshold)

        # Severity logic (LOCKED)
        if attack_prob < self.decision_threshold:
            severity = "Benign"
        elif attack_prob < 0.50:
            severity = "Low"
        elif attack_prob < 0.80:
            severity = "Medium"
        else:
            severity = "High"

        return {
            "attack_probability": round(attack_prob, 6),
            "prediction": prediction,
            "severity": severity
        }
