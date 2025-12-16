# NDR System for Encrypted Traffic Analysis

## 🎯 Project Overview

An **AI-powered Network Detection and Response (NDR)** system that analyzes encrypted network traffic using machine learning to detect malicious activity without decrypting payload data.

### Key Features
- ✅ **99.93% Detection Accuracy** using Random Forest classifier
- ✅ **Real-time Flow Analysis** with Scapy packet capture
- ✅ **Metadata-based Detection** (packet sizes, timing, flow statistics)
- ✅ **Professional Visualizations** (confusion matrix, ROC curve, feature importance)
- ✅ **Production-ready Code** with modular architecture

---

## 📁 Project Structure

```
NDR-Encrypted-Traffic/
├── data/
│   ├── raw/              # Original PCAP files (benign & malicious)
│   └── processed/        # Processed CSV dataset
├── models/               # Trained ML models (.pkl)
├── reports/              # Performance metrics and visualizations
├── src/
│   ├── features.py       # Feature extraction from PCAPs
│   └── detector.py       # Real-time detection engine
├── tools/
│   ├── fetch_samples.py  # Download sample traffic
│   ├── make_dataset.py   # Build labeled dataset
│   ├── train_model.py    # Basic model training
│   └── train_advanced.py # Advanced training with visualizations
└── requirements.txt
```

---

## 🚀 Quick Start

### 1. Setup Environment

```bash
# Clone the repository
git clone https://github.com/omar1111eamsa/NDR-Encrypted-Traffic.git
cd NDR-Encrypted-Traffic

# Create virtual environment
python3 -m venv .env
source .env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Acquire Data

```bash
python3 tools/fetch_samples.py
```

### 3. Build Dataset

```bash
PYTHONPATH=. python3 tools/make_dataset.py
```

### 4. Train Model

```bash
# Basic training
python3 tools/train_model.py

# Advanced training with visualizations
python3 tools/train_advanced.py
```

### 5. Run Detector

```bash
# Test on malicious traffic
PYTHONPATH=. python3 src/detector.py

# To test on benign traffic, modify line 111 in src/detector.py
```

---

## 📊 Performance Metrics

| Metric | Value |
|--------|-------|
| **Accuracy** | 99.93% |
| **ROC AUC** | 1.0000 |
| **Precision (Benign)** | 0.96 |
| **Precision (Malicious)** | 1.00 |
| **Recall (Benign)** | 0.96 |
| **Recall (Malicious)** | 1.00 |

See `reports/` folder for detailed visualizations.

---

## 🔬 How It Works

### Feature Extraction
The system extracts 13 statistical features from network flows:
- Flow duration, bytes/sec, packets/sec
- Packet length statistics (mean, std, min, max)
- Inter-arrival time statistics (mean, std)
- Port numbers and protocol

### Machine Learning Model
- **Algorithm**: Random Forest (100 estimators)
- **Class Balancing**: Weighted classes to handle imbalance
- **Validation**: 80/20 train-test split with stratification

### Detection Pipeline
1. Capture packets using Scapy
2. Group packets into flows (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)
3. Extract features when flow reaches 10 packets
4. Classify using trained Random Forest model
5. Display alert with color coding (red=malicious, green=benign)

---

## 🛠️ Technologies Used

- **Python 3.12**
- **Scapy 2.6.1** - Packet manipulation and capture
- **Pandas 2.3.3** - Data processing
- **NumPy 2.3.5** - Numerical computing
- **Scikit-learn 1.8.0** - Machine learning
- **Matplotlib 3.10.8** - Visualizations
- **Joblib 1.5.3** - Model persistence
- **Requests 2.32.5** - HTTP library for data acquisition

---

## 📝 Future Improvements

- [ ] Add SMOTE for better class balancing
- [ ] Implement hyperparameter tuning (GridSearchCV)
- [ ] Add real-time network interface sniffing
- [ ] Create web dashboard for monitoring
- [ ] Add support for more traffic types (IoT, VoIP, etc.)
- [ ] Implement anomaly detection for zero-day threats

---

## 📄 License

This project is for educational purposes.

---

## 👤 Author

Developed as part of an advanced ML cybersecurity training program.

**Last Updated**: December 2025
