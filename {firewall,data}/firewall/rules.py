"""Layer 1: fast rule-based detection (regex + heuristics)."""
import re
import unicodedata

# (name, regex, weight 0-1, OWASP LLM Top 10 category)
RULES = [
    ("override_instructions",
     r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|any|your)\b.{0,30}\b(instructions?|rules?|prompts?|guidelines?|directions?)\b",
     0.90, "LLM01 Prompt Injection"),
    ("reveal_system_prompt",
     r"\b(reveal|show|print|repeat|display|leak|output)\b.{0,40}\b(system|hidden|initial|original)\b.{0,15}\b(prompt|instructions?|message)\b",
     0.85, "LLM07 System Prompt Leakage"),
    ("role_hijack",
     r"\byou are now\b|\bact as\b.{0,30}\b(unrestricted|unfiltered|jailbroken|evil)\b|\bpretend (to be|you are)\b.{0,60}\b(no|without)\b.{0,20}\b(rules|restrictions|filters|limits)\b",
     0.80, "LLM01 Prompt Injection"),
    ("jailbreak_keywords",
     r"\b(do anything now|developer mode (enabled|on)|jailbreak(ed)? mode|dan mode)\b",
     0.80, "LLM01 Prompt Injection"),
    ("delimiter_injection",
     r"(<\|?(system|im_start|im_end)\|?>|\[/?inst\]|###\s*(system|instruction))",
     0.80, "LLM01 Prompt Injection"),
    ("markdown_exfiltration",
     r"!\[[^\]]*\]\(https?://[^)]*\?[^)]*=",
     0.80, "LLM02 Sensitive Information Disclosure"),
    ("encoded_payload",
     r"\b(base64|rot13|hex)\b.{0,30}\b(decode|decoded|execute|follow)\b",
     0.50, "LLM01 Prompt Injection"),
    ("secrets_request",
     r"\b(api[ _-]?key|password|secret|token|credentials?)\b.{0,30}\b(reveal|show|give|tell|print|send)\b|\b(reveal|show|give|tell|print|send)\b.{0,30}\b(api[ _-]?key|secrets?|credentials?)\b",
     0.60, "LLM02 Sensitive Information Disclosure"),
]
COMPILED = [(n, re.compile(p, re.I | re.S), w, c) for n, p, w, c in RULES]
INVISIBLE = re.compile("[\u200b-\u200f\u2060\ufeff\u202a-\u202e]")


def normalize(text: str) -> str:
    """NFKC-normalize and strip invisible chars so obfuscation doesn't bypass rules."""
    text = unicodedata.normalize("NFKC", text)
    return INVISIBLE.sub("", text)


def scan(text: str):
    """Return (score, hits). Score combines hits as 1 - prod(1 - w)."""
    hits = []
    raw_invisible = len(INVISIBLE.findall(text))
    clean = normalize(text)
    for name, rx, w, cat in COMPILED:
        if rx.search(clean):
            hits.append({"rule": name, "weight": w, "owasp": cat})
    if raw_invisible >= 3:
        hits.append({"rule": "invisible_characters", "weight": 0.6,
                     "owasp": "LLM01 Prompt Injection"})
    miss = 1.0
    for h in hits:
        miss *= 1 - h["weight"]
    return 1 - miss, hits
