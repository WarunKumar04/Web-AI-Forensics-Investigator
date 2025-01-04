# Web Forensics AI Investigator

The **Web Forensics AI Investigator** is an AI-powered tool designed to detect and classify web application attacks by analyzing web server logs and network traffic (PCAP files). Leveraging machine learning, it automates the detection of vulnerabilities like SQL Injection, Cross-Site Scripting (XSS), and Remote File Inclusion (RFI), providing accurate insights for forensic investigations.

---

## Features

- **Log Analysis**:
  - Parses web server logs (Apache/Nginx) to detect attack patterns.
  - Detects attacks like SQL Injection, XSS, RFI, and Path Traversal.

- **PCAP Analysis**:
  - Analyzes network traffic using Pyshark.
  - Extracts HTTP requests and identifies attack indicators.

- **Machine Learning Integration**:
  - Classifies log entries as "Normal" or "Malicious" using trained models.
  - Supports advanced feature extraction with TF-IDF vectorization.

- **Automated Reporting**:
  - Generates detailed PDF reports summarizing detected attacks and their frequencies.
  - Provides actionable recommendations for mitigation.

---

## System Architecture

1. **Data Collection**:
   - Gathers raw web server logs and PCAP files for analysis.

2. **Preprocessing**:
   - Cleans and tokenizes logs.
   - Extracts HTTP requests and relevant features from PCAP files.

3. **Feature Extraction**:
   - Converts logs into numerical features using TF-IDF for ML compatibility.

4. **Model Training**:
   - Trains models like Random Forest or Logistic Regression using labeled data.
   - Saves models as `trained_model.pkl` for future use.

5. **Prediction & Detection**:
   - Classifies logs into attack categories (SQL Injection, XSS, RFI, etc.) or "Normal".

6. **Reporting**:
   - Summarizes findings and generates insights in a comprehensive PDF report.

---

## Key Modules

1. **data_preparation.py**:
   - Processes log and PCAP files into a labeled dataset.

2. **log_parser.py**:
   - Detects attack patterns using functions like:
     - `parse_log_for_sql_injection`
     - `parse_log_for_xss`
     - `parse_log_for_rfi_lfi`

3. **model_trainer.py**:
   - Trains machine learning models and saves them for predictions.

4. **attack_detector.py**:
   - Uses the trained model to classify new log data.

5. **report_generator.py**:
   - Creates a PDF report summarizing detected attacks and recommendations.

---

## How to Use

1. **Setup Environment**:
   - Install required libraries:
     ```bash
     pip install scikit-learn pyshark
     ```

2. **Prepare Data**:
   - Place web logs and PCAP files in the appropriate directories.

3. **Run the Tool**:
   - Execute the following scripts in sequence:
     ```bash
     python data_preparation.py
     python model_trainer.py
     python attack_detector.py
     ```

4. **Generate Report**:
   - Run the report generator:
     ```bash
     python report_generator.py
     ```

---

## Future Enhancements

- **Advanced Models**:
  - Integrate deep learning models like BERT for improved accuracy.

- **Real-Time Monitoring**:
  - Enable real-time log and traffic analysis.

- **Expanded Attack Detection**:
  - Add detection for attacks like CSRF and Command Injection.

- **Enhanced PCAP Analysis**:
  - Perform deeper traffic inspection and anomaly detection.

---


