import pyshark
import os
import re



def parse_all_pcaps(pcap_dir):
    attack_patterns = {
        'SQL Injection': r"union.*select.*from|select.*from.*information_schema.tables|select.*from.*mysql.db",
        'XSS': r"<script>|alert\(|onerror=|document.cookie|eval\(|window.location",
        'RFI/LFI': r"php://input|file://|include|require|eval",
    }

    attack_results = {
        'SQL Injection': [],
        'XSS': [],
        'RFI/LFI': []
    }

    
    for pcap_file in os.listdir(pcap_dir):
        pcap_file_path = os.path.join(pcap_dir, pcap_file)

        if os.path.isfile(pcap_file_path) and pcap_file.endswith('.pcap'):
            print(f"Processing PCAP file: {pcap_file_path}")

            
            cap = pyshark.FileCapture(pcap_file_path, display_filter="http")

            
            for packet in cap:
                if hasattr(packet, 'http'):
                  
                    http_request = packet.http.get_raw_packet().decode(errors='ignore')
                    print(f"Processing HTTP request: {http_request[:200]}...")  

                    
                    for attack_type, pattern in attack_patterns.items():
                        if re.search(pattern, http_request, re.IGNORECASE):
                            attack_results[attack_type].append(http_request)

    return attack_results
