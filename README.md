# Network Detection and Response System for Encrypted Traffic

## Overview

This project implements a machine learning-based Network Detection and Response (NDR) system capable of identifying malicious network traffic in encrypted communications. The system analyzes metadata patterns rather than payload content, achieving 99.93% detection accuracy using a Random Forest classifier.

## Key Features

- Detection accuracy of 99.93% on test dataset
- Real-time flow analysis using Scapy packet capture
- Metadata-based classification (packet sizes, timing, flow statistics)
- Comprehensive performance visualizations and metrics
- Modular architecture for easy extension

## Project Structure

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

## Installation

Clone the repository and set up the environment:

```bash
git clone https://github.com/omar1111eamsa/NDR-Encrypted-Traffic.git
cd NDR-Encrypted-Traffic

python3 -m venv .env
source .env/bin/activate

pip install -r requirements.txt
```

## Usage

### Data Acquisition

Download sample PCAP files:

```bash
python3 tools/fetch_samples.py
```

### Dataset Generation

Extract features and create labeled dataset:

```bash
PYTHONPATH=. python3 tools/make_dataset.py
```

### Model Training

Train the Random Forest classifier:

```bash
# Basic training
python3 tools/train_model.py

# Advanced training with visualizations
python3 tools/train_advanced.py
```

### Running the Detector

Test the detector on sample traffic:

```bash
PYTHONPATH=. python3 src/detector.py
```

To test on benign traffic, modify line 111 in `src/detector.py` to point to the benign PCAP file.

## Performance Metrics

| Metric | Value |
|--------|-------|
| Accuracy | 99.93% |
| ROC AUC | 1.0000 |
| Precision (Benign) | 0.96 |
| Precision (Malicious) | 1.00 |
| Recall (Benign) | 0.96 |
| Recall (Malicious) | 1.00 |

Detailed visualizations are available in the `reports/` directory.

## Methodology

### Feature Extraction

The system extracts 13 statistical features from network flows:

- Flow duration, bytes/sec, packets/sec
- Packet length statistics (mean, std, min, max)
- Inter-arrival time statistics (mean, std)
- Port numbers and protocol

### Machine Learning Model

- Algorithm: Random Forest (100 estimators)
- Class balancing: Weighted classes to handle imbalance
- Validation: 80/20 train-test split with stratification

### Detection Pipeline

1. Capture packets using Scapy
2. Group packets into flows (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)
3. Extract features when flow reaches 10 packets
4. Classify using trained Random Forest model
5. Display alert with color coding (red=malicious, green=benign)

## Dependencies

- Python 3.12
- Scapy 2.6.1 - Packet manipulation and capture
- Pandas 2.3.3 - Data processing
- NumPy 2.3.5 - Numerical computing
- Scikit-learn 1.8.0 - Machine learning
- Matplotlib 3.10.8 - Visualizations
- Joblib 1.5.3 - Model persistence
- Requests 2.32.5 - HTTP library for data acquisition

## Future Work

- Implement SMOTE for better class balancing
- Add hyperparameter tuning (GridSearchCV)
- Support real-time network interface sniffing
- Create web dashboard for monitoring
- Expand dataset with additional malware families
- Implement anomaly detection for zero-day threats

## License

This project is for educational purposes.

## Author

Developed as part of an advanced ML cybersecurity training program.

Last Updated: December 2025
