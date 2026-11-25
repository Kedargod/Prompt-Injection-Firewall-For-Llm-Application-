"""Usage: python merge_csv.py my_dataset.csv --text-col prompt --label-col label --split train"""
import argparse
from firewall import data_utils

ap = argparse.ArgumentParser()
ap.add_argument("file")
ap.add_argument("--text-col", required=True)
ap.add_argument("--label-col", required=True)
ap.add_argument("--split", default="train", choices=["train", "test"])
a = ap.parse_args()
with open(a.file, encoding="utf-8", newline="") as f:
    print(data_utils.merge(f.read(), a.text_col, a.label_col, a.split))
print("Now run: python train.py && python evaluate.py")
