import os
import csv
import json
from config import Labeled_DATA_CSV, Labeled_DATA_JSON, PCAP_DIR
from config import LOG_DIR  
from log_parser import parse_log_for_sql_injection, parse_log_for_xss, parse_log_for_csrf, parse_log_for_rfi_lfi, parse_log_for_command_injection, parse_log_for_path_traversal
import pcap_parser  


output_dir = os.path.dirname(Labeled_DATA_CSV)
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

def prepare_dataset(log_dir=LOG_DIR, output_file=Labeled_DATA_CSV, pcap_dir=PCAP_DIR):
    """
    This function reads log files and PCAP files, labels them according to the detected attack types,
    and saves the labeled data in a CSV format for training the model.
    """
    all_logs = []
    all_labels = []

    
    print(f"Processing files in {log_dir}...")  
    for log_file in os.listdir(log_dir):
        log_file_path = os.path.join(log_dir, log_file)

        if os.path.isfile(log_file_path) and log_file.endswith('.log'):
            print(f"Processing file: {log_file_path}...") 

            
            with open(log_file_path, 'r') as file:
                logs = file.readlines()

            for line in logs:
                print(f"Processing log line: {line.strip()}")  

                
                attack_type = 'Normal'  
                if parse_log_for_sql_injection(line):
                    attack_type = 'SQL Injection'
                elif parse_log_for_xss(line):
                    attack_type = 'XSS'
                elif parse_log_for_csrf(line):
                    attack_type = 'CSRF'
                elif parse_log_for_rfi_lfi(line):
                    attack_type = 'RFI/LFI'
                elif parse_log_for_command_injection(line):
                    attack_type = 'Command Injection'
                elif parse_log_for_path_traversal(line):
                    attack_type = 'Path Traversal'

                
                all_logs.append(line.strip())  
                all_labels.append(attack_type)

    
    pcap_results = pcap_parser.parse_all_pcaps(pcap_dir)  
    print(f"Detected attack patterns in PCAP files: {pcap_results}")

    for attack_type, patterns in pcap_results.items():
        for pattern in patterns:
            all_logs.append(pattern.strip())  
            all_labels.append(attack_type)  

    
    if all_logs:
        with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Log', 'Label'])  
            for log, label in zip(all_logs, all_labels):
                writer.writerow([log, label])

        print(f"Labeled dataset saved to {output_file}")
    else:
        print(f"No logs processed. Please check the log files.")

def prepare_dataset_json(log_dir=LOG_DIR, output_file=Labeled_DATA_JSON, pcap_dir=PCAP_DIR):
    """
    This function reads log files and PCAP files, labels them, and saves the labeled data in a JSON format for training.
    """
    all_data = []

   
    output_dir = os.path.dirname(Labeled_DATA_JSON)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

   
    print(f"Processing files in {log_dir}...")  
    for log_file in os.listdir(log_dir):
        log_file_path = os.path.join(log_dir, log_file)

        if os.path.isfile(log_file_path) and log_file.endswith('.log'):
            print(f"Processing file: {log_file_path}...")  

           
            with open(log_file_path, 'r') as file:
                logs = file.readlines()

            for line in logs:
                print(f"Processing log line: {line.strip()}")  
               
                attack_type = 'Normal' 
                if parse_log_for_sql_injection(line):
                    attack_type = 'SQL Injection'
                elif parse_log_for_xss(line):
                    attack_type = 'XSS'
                elif parse_log_for_csrf(line):
                    attack_type = 'CSRF'
                elif parse_log_for_rfi_lfi(line):
                    attack_type = 'RFI/LFI'
                elif parse_log_for_command_injection(line):
                    attack_type = 'Command Injection'
                elif parse_log_for_path_traversal(line):
                    attack_type = 'Path Traversal'

               
                all_data.append({
                    'log': line.strip(),  
                    'label': attack_type
                })

    
    pcap_results = pcap_parser.parse_all_pcaps(pcap_dir)  
    print(f"Detected attack patterns in PCAP files: {pcap_results}")

    for attack_type, patterns in pcap_results.items():
        for pattern in patterns:
            all_data.append({
                'log': pattern.strip(),  
                'label': attack_type  
            })

    
    if all_data:
        with open(output_file, 'w', encoding='utf-8') as jsonfile:
            json.dump(all_data, jsonfile, indent=4)

        print(f"Labeled dataset saved to {output_file}")
    else:
        print(f"No logs processed. Please check the log files.")


if __name__ == "__main__":
    
    prepare_dataset(LOG_DIR)  
    
