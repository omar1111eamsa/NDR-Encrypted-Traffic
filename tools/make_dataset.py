import os
import pandas as pd
from src.features import FeatureExtractor

# Configuration
RAW_DIR = "data/raw"
PROCESSED_DIR = "data/processed"
OUTPUT_FILE = os.path.join(PROCESSED_DIR, "dataset.csv")

def process_folder(folder_path, label):
    """
    Scans a folder for .pcap files, extracts features, and adds the label.
    """
    dfs = []
    if not os.path.exists(folder_path):
        print(f"[!] Folder not found: {folder_path}")
        return pd.DataFrame()

    # Loop over all files in the folder
    for filename in os.listdir(folder_path):
        if filename.endswith(".pcap"):
            path = os.path.join(folder_path, filename)
            extractor = FeatureExtractor(path)
            
            # Extract features
            df = extractor.extract()
            
            if not df.empty:
                # Add label column (0 for Benign, 1 for Malicious)
                df['label'] = label
                dfs.append(df)
            
    if dfs:
        return pd.concat(dfs, ignore_index=True)
    return pd.DataFrame()

if __name__ == "__main__":
    # Create output directory
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    
    print("--- Building Dataset ---")
    
    print("[*] Processing Benign Traffic (Label 0)...")
    df_benign = process_folder(os.path.join(RAW_DIR, "benign"), 0)
    
    print("[*] Processing Malicious Traffic (Label 1)...")
    df_malicious = process_folder(os.path.join(RAW_DIR, "malicious"), 1)
    
    # Combine both
    full_df = pd.concat([df_benign, df_malicious], ignore_index=True)
    
    # Save
    print(f"[*] Saving {len(full_df)} flows to {OUTPUT_FILE}...")
    full_df.to_csv(OUTPUT_FILE, index=False)
    print("[+] Dataset creation complete.")