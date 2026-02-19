import pandas as pd
import joblib
import json
import os
from datetime import datetime

class AlertEngine:
    def __init__(self, model_dir, mapping_path):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.rf_model = joblib.load(os.path.join(model_dir, "supervised_rf.joblib"))
        self.an_model = joblib.load(os.path.join(model_dir, "anomaly_if.joblib"))
        # Load label encoder
        le_path = os.path.join(base_dir, "data", "processed", "label_encoder.joblib")
        self.le = joblib.load(le_path)
        
        with open(mapping_path, 'r') as f:
            self.mapping = json.load(f)

    def generate_alert(self, features):
        # features is a 2D numpy array/dataframe row
        rf_pred = self.rf_model.predict(features)[0]
        an_pred = self.an_model.predict(features)[0] # -1 for anomaly, 1 for normal
        
        attack_type = self.le.inverse_transform([rf_pred])[0]
        confidence = max(self.rf_model.predict_proba(features)[0])
        
        mitre_info = self.mapping.get(attack_type, self.mapping["BENIGN"])
        
        # If supervised says BENIGN but anomaly says anomaly, elevate
        if attack_type == "BENIGN" and an_pred == -1:
            attack_type = "Anomaly"
            mitre_info = self.mapping["Anomaly"]
            confidence = 0.85 # Heuristic for anomaly
            
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert_id": os.urandom(4).hex(),
            "type": attack_type,
            "severity": mitre_info["severity"],
            "confidence": round(float(confidence), 2),
            "mitre_technique": mitre_info["technique_id"],
            "technique_name": mitre_info["technique_name"],
            "description": mitre_info["description"]
        }
        
        return alert

if __name__ == "__main__":
    # Test alert generation
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    engine = AlertEngine(os.path.join(base_dir, "models", "saved"), 
                         os.path.join(base_dir, "mitre", "attack_mapping.json"))
    
    # Load sample and test first row
    sample = pd.read_csv(os.path.join(base_dir, "data", "processed", "cleaned_data.csv")).drop('Label_Enc', axis=1).iloc[[0]]
    print(json.dumps(engine.generate_alert(sample), indent=2))
