
import log_parser
import pcap_parser
import data_preparation
import model_trainer
import attack_detector
import report_generator

def run_full_analysis():
    print("Parsing logs for attacks...")
    log_parser.parse_all_logs()  

    print("Parsing PCAP files for network traffic analysis...")
    pcap_parser.parse_all_pcaps()  

    print("Preparing labeled dataset...")
    data_preparation.prepare_dataset('./data/access_logs')  

    print("Training the model...")
    model_trainer.train_model() 

    print("Detecting attacks in logs...")
    attack_detector.detect_attacks()  

    print("Generating report...")
    report_generator.generate_report()  

if __name__ == "__main__":
    run_full_analysis()
