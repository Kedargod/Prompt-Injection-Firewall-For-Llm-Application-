"""Combines layers and makes the block/allow decision."""
import os
import re
import time
from . import rules, classifier

CANARY = "CANARY-7f3a9c"  # planted in the system prompt; if it shows up in output, it leaked


class Firewall:
    def __init__(self, threshold=0.70, use_rules=True, use_ml=True):
        self.threshold = threshold
        self.use_rules = use_rules
        self.use_ml = use_ml
        self.model = None
        if use_ml:
            if not os.path.exists(classifier.MODEL_PATH):
                raise RuntimeError("model.joblib missing. Run: python train.py")
            self.model = classifier.load()

    def check_input(self, text: str) -> dict:
        t0 = time.perf_counter()
        rule_score, hits, ml_score = 0.0, [], 0.0
        if self.use_rules:
            rule_score, hits = rules.scan(text)
        if self.use_ml:
            ml_score = classifier.score(self.model, rules.normalize(text))
        final = max(rule_score, ml_score)
        return {
            "blocked": final >= self.threshold,
            "score": round(final, 3),
            "rule_score": round(rule_score, 3),
            "ml_score": round(ml_score, 3),
            "rule_hits": hits,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
        }

    @staticmethod
    def check_output(text: str) -> dict:
        """Output guard: catch system prompt leaks and secret-looking strings."""
        leaked = CANARY in text
        secret = bool(re.search(r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})", text))
        return {"blocked": leaked or secret,
                "reason": "canary_leak" if leaked else ("secret_pattern" if secret else None)}
