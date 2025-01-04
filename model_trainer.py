import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib


def train_model(dataset_path='output/labeled_data.csv'):
    
    data = pd.read_csv(dataset_path)

    
    X = data['Log']
    y = data['Label']

    
    from sklearn.feature_extraction.text import TfidfVectorizer
    vectorizer = TfidfVectorizer(max_features=1000)
    X_vec = vectorizer.fit_transform(X)

   
    X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.3, random_state=42)

    
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

   
    y_pred = clf.predict(X_test)

    
    print("Classification Report:")
    print(classification_report(y_test, y_pred))

    
    joblib.dump(clf, 'output/trained_model.pkl')
    joblib.dump(vectorizer, 'output/tfidf_vectorizer.pkl')
    print("Model and vectorizer saved to disk.")


if __name__ == "__main__":
    train_model()
