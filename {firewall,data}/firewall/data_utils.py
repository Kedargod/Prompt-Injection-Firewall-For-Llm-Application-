"""Merge an external CSV into data/train.csv or data/test.csv."""
import csv
import io
import os

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
ATTACK_WORDS = {"1", "true", "attack", "injection", "prompt injection", "jailbreak", "malicious", "unsafe", "harmful"}
BENIGN_WORDS = {"0", "false", "benign", "safe", "normal", "legit", "legitimate"}


def _to_label(v):
    v = str(v).strip().lower()
    if v in ATTACK_WORDS: return 1
    if v in BENIGN_WORDS: return 0
    return None


def merge(csv_text: str, text_col: str, label_col: str, split: str = "train"):
    """Append rows from csv_text to data/<split>.csv. Returns a summary dict."""
    if split not in ("train", "test"):
        raise ValueError("split must be 'train' or 'test'")
    path = os.path.join(DATA_DIR, f"{split}.csv")
    with open(path, newline="", encoding="utf-8") as f:
        existing = {r["text"].strip() for r in csv.DictReader(f)}

    reader = csv.DictReader(io.StringIO(csv_text))
    if text_col not in (reader.fieldnames or []) or label_col not in reader.fieldnames:
        raise ValueError(f"Columns not found. File has: {reader.fieldnames}")

    added = skipped = 0
    new_rows = []
    for row in reader:
        text, label = (row[text_col] or "").strip(), _to_label(row[label_col])
        if not text or label is None or text in existing:
            skipped += 1
            continue
        existing.add(text)
        new_rows.append([label, "external", text])
        added += 1
    with open(path, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(new_rows)
    return {"split": split, "added": added, "skipped": skipped}
