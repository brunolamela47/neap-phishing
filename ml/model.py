
# ml/model.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# ML Model — Load and Predict
# ─────────────────────────────────────────

import pickle
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')

# ─── Load Model ───
def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Model not found. Run ml/train.py first.")

    with open(MODEL_PATH, 'rb') as f:
        return pickle.load(f)

# ─── Predict ───
def predict(text: str) -> dict:
    try:
        pipeline = load_model()

        prediction = pipeline.predict([text])[0]
        probability = pipeline.predict_proba([text])[0]

        is_phishing = int(prediction) == 1
        confidence  = round(float(max(probability)) * 100, 2)
        ml_score    = round(float(probability[1]) * 100, 2)

        return {
            "is_phishing": is_phishing,
            "confidence":  confidence,
            "ml_score":    ml_score,
            "prediction":  "PHISHING" if is_phishing else "LEGITIMATE"
        }

    except Exception as e:
        return {
            "is_phishing": False,
            "confidence":  0,
            "ml_score":    0,
            "prediction":  "UNKNOWN",
            "error":       str(e)
        }


# ─── Quick Test ───
if __name__ == "__main__":
    tests = [
        "Your account has been suspended. Click here to verify your password immediately.",
        "Hi team, the meeting is scheduled for Monday at 10am. See you there!",
        "Congratulations! You won a prize. Enter your bank details to claim it now."
    ]

    for text in tests:
        result = predict(text)
        print(f"\nText: {text[:60]}...")
        print(f"Prediction: {result['prediction']}")
        print(f"ML Score:   {result['ml_score']}%")
        print(f"Confidence: {result['confidence']}%")