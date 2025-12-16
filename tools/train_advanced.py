import pandas as pd
import joblib
import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, 
    accuracy_score, 
    confusion_matrix,
    roc_curve,
    roc_auc_score
)
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for server environments

# Paths
DATA_PATH = "data/processed/dataset.csv"
MODEL_PATH = "models/model.pkl"
REPORTS_DIR = "reports"

def plot_confusion_matrix(y_true, y_pred, save_path):
    """Generate and save confusion matrix visualization"""
    cm = confusion_matrix(y_true, y_pred)
    
    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    
    # Labels
    classes = ['Benign', 'Malicious']
    ax.set(xticks=np.arange(cm.shape[1]),
           yticks=np.arange(cm.shape[0]),
           xticklabels=classes, yticklabels=classes,
           title='Confusion Matrix',
           ylabel='True Label',
           xlabel='Predicted Label')
    
    # Add text annotations
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], 'd'),
                   ha="center", va="center",
                   color="white" if cm[i, j] > thresh else "black")
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[+] Confusion matrix saved to {save_path}")

def plot_roc_curve(y_true, y_proba, save_path):
    """Generate and save ROC curve"""
    fpr, tpr, _ = roc_curve(y_true, y_proba)
    auc = roc_auc_score(y_true, y_proba)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, 
             label=f'ROC curve (AUC = {auc:.4f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', 
             label='Random Classifier')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[+] ROC curve saved to {save_path}")

def plot_feature_importance(clf, feature_names, save_path):
    """Generate and save feature importance plot"""
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    plt.figure(figsize=(10, 6))
    plt.title("Feature Importance")
    plt.bar(range(len(importances)), importances[indices])
    plt.xticks(range(len(importances)), 
               [feature_names[i] for i in indices], 
               rotation=45, ha='right')
    plt.ylabel('Importance Score')
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[+] Feature importance saved to {save_path}")

def train():
    print("[*] Loading dataset...")
    if not os.path.exists(DATA_PATH):
        print("[-] Dataset not found! Run tools/make_dataset.py first.")
        return

    df = pd.read_csv(DATA_PATH)
    
    # Feature Selection
    X = df.drop(columns=['src_ip', 'dst_ip', 'label'])
    y = df['label']
    feature_names = X.columns.tolist()
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"[*] Training on {len(X_train)} samples, Testing on {len(X_test)} samples...")
    print(f"[*] Class distribution - Train: {np.bincount(y_train)}, Test: {np.bincount(y_test)}")
    
    # Initialize Random Forest with optimized parameters
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'  # Handle class imbalance
    )
    
    # Train
    print("[*] Training model...")
    clf.fit(X_train, y_train)
    
    # Predict
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]  # Probability of malicious class
    
    # Evaluate
    acc = accuracy_score(y_test, y_pred)
    print(f"\n{'='*60}")
    print(f"[+] Accuracy: {acc:.4f}")
    print(f"{'='*60}")
    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
    
    # Create reports directory
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Generate visualizations
    print(f"\n[*] Generating visualizations...")
    plot_confusion_matrix(y_test, y_pred, f"{REPORTS_DIR}/confusion_matrix.png")
    plot_roc_curve(y_test, y_proba, f"{REPORTS_DIR}/roc_curve.png")
    plot_feature_importance(clf, feature_names, f"{REPORTS_DIR}/feature_importance.png")
    
    # Save metrics to text file
    with open(f"{REPORTS_DIR}/metrics.txt", 'w') as f:
        f.write(f"Model Performance Metrics\n")
        f.write(f"{'='*60}\n\n")
        f.write(f"Accuracy: {acc:.4f}\n\n")
        f.write("Classification Report:\n")
        f.write(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
        f.write(f"\nROC AUC Score: {roc_auc_score(y_test, y_proba):.4f}\n")
    
    print(f"[+] Metrics saved to {REPORTS_DIR}/metrics.txt")
    
    # Save Model
    print(f"\n[*] Saving model to {MODEL_PATH}...")
    joblib.dump(clf, MODEL_PATH)
    print("[+] Training complete!")
    print(f"\n📊 Check the '{REPORTS_DIR}/' folder for visualizations and metrics.")

if __name__ == "__main__":
    train()