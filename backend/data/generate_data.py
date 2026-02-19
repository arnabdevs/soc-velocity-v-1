import pandas as pd
import numpy as np
import os

def generate_synthetic_data(output_path):
    np.random.seed(42)
    n_samples = 2000
    
    # Features
    flow_duration = np.random.uniform(10, 50000, n_samples)
    tot_fwd_pkts = np.random.randint(1, 100, n_samples)
    tot_bwd_pkts = np.random.randint(0, 100, n_samples)
    tot_len_fwd_pkts = tot_fwd_pkts * np.random.uniform(40, 1500, n_samples)
    tot_len_bwd_pkts = tot_bwd_pkts * np.random.uniform(40, 1500, n_samples)
    flow_byts_s = (tot_len_fwd_pkts + tot_len_bwd_pkts) / (flow_duration / 1000)
    flow_pkts_s = (tot_fwd_pkts + tot_bwd_pkts) / (flow_duration / 1000)
    
    # Base DataFrame
    data = pd.DataFrame({
        'Flow Duration': flow_duration,
        'Total Fwd Packets': tot_fwd_pkts,
        'Total Backward Packets': tot_bwd_pkts,
        'Total Length of Fwd Packets': tot_len_fwd_pkts,
        'Total Length of Bwd Packets': tot_len_bwd_pkts,
        'Flow Bytes/s': flow_byts_s,
        'Flow Packets/s': flow_pkts_s,
        'Label': ['BENIGN'] * n_samples
    })

    # Injecting Port Scan (High packet rate, short duration)
    port_scan_idx = np.random.choice(n_samples, 200, replace=False)
    data.loc[port_scan_idx, 'Flow Duration'] = np.random.uniform(1, 100, 200)
    data.loc[port_scan_idx, 'Flow Packets/s'] = np.random.uniform(1000, 5000, 200)
    data.loc[port_scan_idx, 'Label'] = 'PortScan'

    # Injecting Brute Force (High fwd packets, consistent pattern)
    brute_force_idx = np.random.choice(list(set(range(n_samples)) - set(port_scan_idx)), 150, replace=False)
    data.loc[brute_force_idx, 'Total Fwd Packets'] = np.random.randint(500, 1000, 150)
    data.loc[brute_force_idx, 'Flow Duration'] = np.random.uniform(10000, 30000, 150)
    data.loc[brute_force_idx, 'Label'] = 'BruteForce'

    data.to_csv(output_path, index=False)
    print(f"Synthetic data generated at {output_path}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "data")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    generate_synthetic_data(os.path.join(output_dir, "cicids_sample.csv"))
