import requests
import os

SAMPLES = {
    "benign": ("https://github.com/markofu/hackeire/raw/master/2011/pcap/c1.pcap", "data/raw/benign/sample_benign.pcap"),
    "malicious": ("https://github.com/markofu/hackeire/raw/master/2011/pcap/c2.pcap", "data/raw/malicious/sample_malicious.pcap")
}

def download_pcap(url, dest_path):
    if os.path.exists(dest_path):
        print(f"[!] File already exists: {dest_path}")
        return

    print(f"[*] Downloading {url}...")
    try:
        response = requests.get(url, stream=True, timeout=10)
        response.raise_for_status()

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        with open(dest_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"[+] Success: Download to {dest_path}")

    except Exception as e:
        print(f"[-] Failed to download {url}: {e}")

if __name__ == "__main__":
    print("--- Starting Data Acquisition ---")
    for traffic_type, (url, path) in SAMPLES.items():
        download_pcap(url, path)
    print("--- Acquisition Complete ---")
        