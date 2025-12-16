import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
import numpy as np
from collections import defaultdict
import os

class FeatureExtractor:
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path

    def extract(self):
        """
        Reads the PCAP and extracts statistical features for each flow.
        Returns a Pandas DataFrame.
        """

        print(f"[*] Parsing file: {self.pcap_path} ...")
        try:
            packets = rdpcap(self.pcap_path)
        except Exception as e:
            print(f"[-] Failed reading PCAP: {e}")
            return pd.DataFrame()

        flows = defaultdict(list)

        for pkt in packets:
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
                flows[flow_id].append(pkt)

        print(f"[+] Found {len(flows)} streams")

        data = []

        for flow_id, pkt_list in flows.items():
            src_ip, dst_ip, sport, dport, proto = flow_id

            sizes = [len(p) for p in pkt_list]

            timestamps = [float(p.time) for p in pkt_list]

            if len(timestamps) > 1:
                iat = np.diff(timestamps)

                iat_mean = np.mean(iat)
                iat_std = np.std(iat)
                
            else:
                iat_mean = 0
                iat_std = 0

            duration = timestamps[-1] - timestamps[0] if len(timestamps) > 0 else 0


            features = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
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

            data.append(features)
        return pd.DataFrame(data)

# Test block (only runs if executed directly)
if __name__ == "__main__":
    # Test on one of our benign samples
    test_path = "data/raw/benign/sample_benign.pcap"
    if os.path.exists(test_path):
        extractor = FeatureExtractor(test_path)
        df = extractor.extract()
        print(df.head())
        print(f"Extracted shape: {df.shape}")
    else:
        print("Test file not found! Run tools/fetch_samples.py first.")

            
