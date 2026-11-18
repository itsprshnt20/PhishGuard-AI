
"""Fit and evaluate on bundled synthetic text. Imported mail is inference-only."""
import csv
from pathlib import Path

DATA = Path(__file__).resolve().parent / "samples" / "synthetic_training.csv"
EVALUATION_FAMILIES = {"normal-10", "normal-11", "normal-12", "phish-4"}


def load_split():
    with DATA.open(encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    train = [row for row in rows if row["family"] not in EVALUATION_FAMILIES]
    evaluation = [row for row in rows if row["family"] in EVALUATION_FAMILIES]
    return train, evaluation


def train_model():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline

    train, _ = load_split()
    pipeline = make_pipeline(TfidfVectorizer(ngram_range=(1, 2)),
                             LogisticRegression(random_state=42))
    return pipeline.fit([row["text"] for row in train], [row["label"] for row in train])


def score(pipeline, email):
    content = email.headers.get("Subject", "") + "\n" + email.body
    index = list(pipeline.classes_).index("phishing")
    return float(pipeline.predict_proba([content])[0, index])


def main():
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

    _, evaluation = load_split()
    actual = [row["label"] for row in evaluation]
    predicted = train_model().predict([row["text"] for row in evaluation])
    print(f"Synthetic held-out examples: {len(actual)}")
    print(f"Accuracy: {accuracy_score(actual, predicted):.3f}")
    print(f"Phishing F1: {f1_score(actual, predicted, pos_label='phishing'):.3f}")
    print("Confusion matrix (rows actual, columns predicted; normal, phishing):")
    print(confusion_matrix(actual, predicted, labels=["normal", "phishing"]))


if __name__ == "__main__":
    main()
