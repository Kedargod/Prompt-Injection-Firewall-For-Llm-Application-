"""Benchmark each layer separately and combined on data/test.csv."""
from firewall.engine import Firewall
from firewall.classifier import load_csv

X, y = load_csv("data/test.csv")


def run(name, **kw):
    fw = Firewall(**kw)
    tp = fp = fn = tn = 0
    lat = []
    for text, label in zip(X, y):
        r = fw.check_input(text)
        lat.append(r["latency_ms"])
        if label and r["blocked"]: tp += 1
        elif label: fn += 1
        elif r["blocked"]: fp += 1
        else: tn += 1
    det = tp / max(tp + fn, 1) * 100
    fpr = fp / max(fp + tn, 1) * 100
    print(f"{name:<18} detection={det:5.1f}%  false_pos={fpr:5.1f}%  "
          f"avg_latency={sum(lat)/len(lat):6.2f}ms  (TP={tp} FN={fn} FP={fp} TN={tn})")


print(f"Test set: {sum(y)} attacks, {len(y)-sum(y)} benign\n")
run("Rules only", use_rules=True, use_ml=False)
run("ML only", use_rules=False, use_ml=True)
run("Rules + ML", use_rules=True, use_ml=True)
