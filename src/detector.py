import pandas as pd
import joblib
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import datetime

# Load Model
MODEL_PATH = "models/model.pkl"
try:
    clf = joblib.load(MODEL_PATH)
    print(f"[*] Model loaded from {MODEL_PATH}")
except Exception as e:
    print(f"[-] Error loading model: {e}")
    exit(1)

# Active flows buffer
# Key: Tuple(src_ip, dst_ip, src_port, dst_port, proto)
# Value: List of packets
current_flows = defaultdict(list)

def extract_features(flow_id, packets):
    """
    Same logic as src/features.py but for a single list of packets in memory.
    """
    src_ip, dst_ip, sport, dport, proto = flow_id
    sizes = [len(p) for p in packets]
    timestamps = [float(p.time) for p in packets]
    
    duration = timestamps[-1] - timestamps[0] if len(timestamps) > 0 else 0
    
    if len(timestamps) > 1:
        iat = np.diff(timestamps)
        iat_mean = np.mean(iat)
        iat_std = np.std(iat)
    else:
        iat_mean = 0.0
        iat_std = 0.0

    features = {
        'src_port': sport,
        'dst_port': dport,
        'protocol': proto,
        'flow_duration': duration,
        'flow_byts_s': sum(sizes) / duration if duration > 0 else 0,
        'flow_pkts_s': len(sizes) / duration if duration > 0 else 0,
        'fwd_pkts_tot': len(sizes),
        'pkt_len_mean': np.mean(sizes),
        'pkt_len_std': np.std(sizes),
        'pkt_len_min': np.min(sizes),
        'pkt_len_max': np.max(sizes),
        'iat_mean': iat_mean,
        'iat_std': iat_std
    }
    # Reorder columns to match training exactly (alphabetical or specific order matters!)
    # Actually, sklearn models expect the same feature order/names if dataframe.
    return pd.DataFrame([features])

def process_packet(pkt):
    """
    Callback for each captured packet.
    """
    if IP in pkt and (TCP in pkt or UDP in pkt):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        else:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            
        flow_id = (src_ip, dst_ip, sport, dport, proto)
        current_flows[flow_id].append(pkt)
        
        # SIMULATION: In a real NDR, we wait for FIN/RST or Timeout.
        # Here, for demo, if a flow reaches 10 packets, we classify it immediately.
        if len(current_flows[flow_id]) >= 10:
            analyze_flow(flow_id, current_flows[flow_id])
            # Clear to avoid re-analyzing endlessly
            del current_flows[flow_id]

def analyze_flow(flow_id, packets):
    try:
        df = extract_features(flow_id, packets)
        # Ensure correct column order by matching what we trained on
        # Warning: This implies we know the training columns. 
        # Ideally, we should save feature_names with the model.
        # For now, we rely on the dict keys being consistent with features.py
        
        prediction = clf.predict(df)[0]
        
        label = "MALICIOUS" if prediction == 1 else "BENIGN"
        color = "\033[91m" if prediction == 1 else "\033[92m" # Red or Green
        reset = "\033[0m"
        
        src, dst, sport, dport, proto = flow_id
        print(f"{color}[!] DETECTED {label} FLOW: {src}:{sport} -> {dst}:{dport} ({proto}){reset}")
        
    except Exception as e:
        pass # Ignore feature extraction errors for now

if __name__ == "__main__":
    print(f"[*] Starting NDR Detector...")
    print(f"[*] Simulating Live Traffic from: data/raw/malicious/sample_malicious.pcap")
    
    # We use 'sniff(offline=...)' to simulate real-time from our file
    try:
        sniff(offline="data/raw/malicious/sample_malicious.pcap", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping.")