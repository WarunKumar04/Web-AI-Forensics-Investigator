import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

def detect_attacks(log_file = r'D:\web forensics ai investigator\data\access_logs\access_logs.log', model_path='output/trained_model.pkl', vectorizer_path='output/tfidf_vectorizer.pkl'):
   
    clf = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)
    
    with open(log_file, 'r') as file:
        logs = file.readlines()
 
    X = vectorizer.transform(logs)

    predictions = clf.predict(X)

    for log, pred in zip(logs, predictions):
        print(f"Log: {log.strip()} - Prediction: {pred}")

if __name__ == "__main__":
    detect_attacks()
