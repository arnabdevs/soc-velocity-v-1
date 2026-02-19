import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

def train_supervised(data_path, model_dir):
    df = pd.read_csv(data_path)
    X = df.drop('Label_Enc', axis=1)
    y = df['Label_Enc']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest model...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    
    y_pred = rf.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save Graphics
    import matplotlib.pyplot as plt
    import seaborn as sns
    from sklearn.metrics import ConfusionMatrixDisplay
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results_dir = os.path.join(base_dir, "results")
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
        
    # Confusion Matrix
    plt.figure(figsize=(10, 8))
    ConfusionMatrixDisplay.from_predictions(y_test, y_pred, cmap='Blues')
    plt.title("SOC Detection: Confusion Matrix")
    plt.savefig(os.path.join(results_dir, "confusion_matrix.png"))
    plt.close()
    
    # Feature Importance
    plt.figure(figsize=(12, 6))
    importances = rf.feature_importances_
    indices = np.argsort(importances)[::-1]
    sns.barplot(x=importances[indices], y=X.columns[indices], palette="viridis")
    plt.title("SOC Engine: Feature Importance Indicators")
    plt.xlabel("Importance Score")
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "feature_importance.png"))
    plt.close()

    # Save model
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)
    joblib.dump(rf, os.path.join(model_dir, "supervised_rf.joblib"))
    print(f"Model saved to {model_dir}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_file = os.path.join(base_dir, "data", "processed", "cleaned_data.csv")
    model_folder = os.path.join(base_dir, "models", "saved")
    train_supervised(data_file, model_folder)
