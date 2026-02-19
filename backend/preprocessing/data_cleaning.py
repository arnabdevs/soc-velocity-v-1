import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

def clean_data(input_path, output_dir):
    print(f"Loading data from {input_path}...")
    df = pd.read_csv(input_path)
    
    # Drop rows with NaN or infinity
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # Label Encoding
    le = LabelEncoder()
    df['Label_Enc'] = le.fit_transform(df['Label'])
    
    # Save Label Encoder for later use
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    joblib.dump(le, os.path.join(output_dir, "label_encoder.joblib"))
    
    # Feature Scaling
    features = df.drop(['Label', 'Label_Enc'], axis=1)
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)
    
    # Save Scaler
    joblib.dump(scaler, os.path.join(output_dir, "scaler.joblib"))
    
    # Save cleaned data
    cleaned_df = pd.DataFrame(scaled_features, columns=features.columns)
    cleaned_df['Label_Enc'] = df['Label_Enc'].values
    cleaned_df.to_csv(os.path.join(output_dir, "cleaned_data.csv"), index=False)
    
    print(f"Data cleaned and saved to {output_dir}")

if __name__ == "__main__":
    # Use relative paths for portability
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_csv = os.path.join(base_dir, "data", "cicids_sample.csv")
    output_folder = os.path.join(base_dir, "data", "processed")
    
    clean_data(input_csv, output_folder)
