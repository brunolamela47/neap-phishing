# ml/train.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# ML Model Training
# ─────────────────────────────────────────

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.pipeline import Pipeline
import pickle
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATASET_PATH = os.path.join(os.path.dirname(__file__), 'dataset', 'Phishing_Email.csv')
MODEL_PATH   = os.path.join(os.path.dirname(__file__), 'model.pkl')

def train():
    print("Loading dataset...")
    df = pd.read_csv(DATASET_PATH)

    print(f"Dataset shape: {df.shape}")
    print(f"Labels: {df['Email Type'].value_counts().to_dict()}")

    # Drop missing
    df = df.dropna(subset=['Email Text', 'Email Type'])

    X = df['Email Text']
    y = df['Email Type'].map({'Phishing Email': 1, 'Safe Email': 0})

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print(f"Training on {len(X_train)} samples...")

    # Pipeline: TF-IDF + Random Forest
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words='english'
        )),
        ('clf', RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            random_state=42,
            n_jobs=-1
        ))
    ])

    pipeline.fit(X_train, y_train)

    # Evaluate
    y_pred = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n=== MODEL RESULTS ===")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print(f"\n{classification_report(y_test, y_pred, target_names=['Safe Email', 'Phishing Email'])}")

    # Save
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(pipeline, f)

    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()