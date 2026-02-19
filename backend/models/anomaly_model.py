import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

def train_anomaly(data_path, model_dir):
    df = pd.read_csv(data_path)
    X = df.drop('Label_Enc', axis=1)
    
    # Isolation Forest is trained only on "Benign" data in a real scenario, 
    # but here we can train on the whole set to find outliers.
    print("Training Isolation Forest anomaly detector...")
    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    iso_forest.fit(X)
    
    # Save model
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)
    joblib.dump(iso_forest, os.path.join(model_dir, "anomaly_if.joblib"))
    print(f"Anomaly model saved to {model_dir}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_file = os.path.join(base_dir, "data", "processed", "cleaned_data.csv")
    model_folder = os.path.join(base_dir, "models", "saved")
    train_anomaly(data_file, model_folder)
