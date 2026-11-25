"""Layer 2: ML classifier (TF-IDF + Logistic Regression)."""
import csv
import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline, make_union

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model.joblib")


def load_csv(path):
    X, y = [], []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            X.append(row["text"])
            y.append(int(row["label"]))
    return X, y


def train(csv_path):
    X, y = load_csv(csv_path)
    vec = make_union(
        TfidfVectorizer(ngram_range=(1, 2), lowercase=True, sublinear_tf=True),
        TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True),
    )
    model = make_pipeline(vec, LogisticRegression(C=5, max_iter=1000, class_weight="balanced"))
    model.fit(X, y)
    joblib.dump(model, MODEL_PATH)
    return model


def load():
    return joblib.load(MODEL_PATH)


def score(model, text: str) -> float:
    return float(model.predict_proba([text])[0][1])
