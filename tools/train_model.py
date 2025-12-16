import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Paths
DATA_PATH = "data/processed/dataset.csv"
MODEL_PATH = "models/model.pkl"

def train():
    print("[*] Loading dataset...")
    if not os.path.exists(DATA_PATH):
        print("[-] Dataset not found! Run tools/make_dataset.py first.")
        return

    df = pd.read_csv(DATA_PATH)
    
    # Clean data (remove non-numeric columns unrelated to features)
    # keeping IP/Ports to identify flows is okay for debugging, 
    # but for ML we must drop strings or encode them. 
    # For this basic version, we drop IP addresses and Protocol.
    # Ideally, we should keep Protocol (mapped to Int) and Ports.
    
    # Feature Selection: Drop metadata columns that are strings
    X = df.drop(columns=['src_ip', 'dst_ip', 'label'])
    y = df['label'] # Target
    
    # Split: 80% Train, 20% Test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print(f"[*] Training on {len(X_train)} samples, Testing on {len(X_test)} samples...")
    
    # Initialize Random Forest
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    
    # Train
    clf.fit(X_train, y_train)
    
    # Predict
    y_pred = clf.predict(X_test)
    
    # Evaluate
    acc = accuracy_score(y_test, y_pred)
    print(f"[+] Accuracy: {acc:.4f}")
    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred))
    
    # Save Model
    print(f"[*] Saving model to {MODEL_PATH}...")
    joblib.dump(clf, MODEL_PATH)
    print("[+] Done.")

if __name__ == "__main__":
    os.makedirs("models", exist_ok=True)
    train()