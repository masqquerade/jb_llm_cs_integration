import os
from typing import Tuple, List, Iterable

import yaml, re

from src.helpers.math_helper import shannon_entropy
from src.helpers.regex_helper import detect_jwt, is_example_like, detect_dangerous_uri, \
    wordy_or_camel, compression_ratio
from resources.common import JWT_NAMES

# Helper function to build return value of "detect_secrets" function
def build_secret(
        lineNum: int | None,
        _id: int,
        rule: str,
        value: str,
        file_name: str,
        entropy: float,
        context: list,
        commit,
        uri_detected,
        kind):
    return {
        "kind": kind,
        "id": _id,
        "commit": commit,
        "line": lineNum,
        "rule": rule,
        "value": value,
        "file": file_name,
        "entropy": entropy,
        "context": context,
        "uri_detected": uri_detected,
    }

def build_sensitive(
        lineNum: int | None,
        _id: int,
        rule: str,
        value: str,
        file_name: str,
        context,
        commit,
):
    return {
        "id": _id,
        "commit": commit,
        "line": lineNum,
        "rule": rule,
        "value": value,
        "file": file_name,
        "context": context,
    }

# Function which decides, whether a token should be sent to the LLM for detailed analysis
def should_escalate(value: str, line: str, path: str, entropy: float, conf: str) -> bool:
    if conf == "low": return True
    if re.search(r"(.)\1{6,}", value): return True
    if is_example_like(value, line, path): return True
    if wordy_or_camel(value): return True
    if compression_ratio(value) < 0.85: return True
    if len(value) >= 16 and entropy < 4.0: return True

    return False

def select_best_match(matches):
    if not matches:
        return None

    rank = {
        "low": 0,
        "high": 1,
    }

    best = max(matches, key=lambda d: (
        rank.get(str(d.get("conf", "")).lower(), 0),
        len(str(d.get("token", ""))))
    )

    return best

def precompile_patterns(raw_patterns):
    tmp = []

    for p in raw_patterns:
        pattern = p.get("pattern", {})
        confidence = pattern.get("confidence").strip()
        tmp.append((pattern["name"], re.compile(pattern["regex"]), confidence))

    return tmp

def match_line(line: str, rx, name, conf):
    match = rx.search(line)

    if match:
         return {
            "name": name,
            "conf": conf,
            "token": match.group(0),
         }

    return None


class Regex:
    def __init__(self):
        self.last_id = 0

        # Manage secrets database
        secrets_file_path = os.path.join(os.path.dirname(__file__), "../../resources/rules-stable.yml")
        with open(secrets_file_path, "r", encoding="utf-8") as f:
            secrets_db = yaml.safe_load(f)

        secrets_patterns_raw = secrets_db.get("patterns", [])
        self.secrets_patterns_list = precompile_patterns(secrets_patterns_raw)

        # Manage sensitive database
        sensitive_file_path = os.path.join(os.path.dirname(__file__), "../../resources/pii-stable.yml")
        with open(sensitive_file_path, "r", encoding="utf-8") as f:
            sensitive_db = yaml.safe_load(f)

        sensitive_patterns_raw = sensitive_db.get("patterns", [])
        self.sensitive_patterns_list = precompile_patterns(sensitive_patterns_raw)

    def detect_secret(self, line: Tuple[int | None, str, List], file_name, commit):
        # Iterate over all patterns
        hits = []

        for name, rx, conf in self.secrets_patterns_list:
            match = match_line(line[1], rx, name, conf)
            if match:
                hits.append(match)

        best_match = select_best_match(hits)

        if best_match is None:
            return None

        token = best_match["token"]

        _id = self.last_id
        self.last_id += 1

        uri_detected = detect_dangerous_uri(token)
        entropy = shannon_entropy(token)

        # Decide whether the match should be checked by the LLM
        escalate_llm = should_escalate(token, line[1], file_name, entropy, best_match["conf"])

        # Additional check for JWT tokens to reduce LLM-usage
        if best_match["name"] in JWT_NAMES:
            likely_jwt = detect_jwt(token)
            if likely_jwt:
                escalate_llm = False
            else:
                return None

        # Return intermediate result for further analysis
        return build_secret(
            kind=("LLM" if escalate_llm else "Instant"),
            _id=_id,
            commit=commit,
            lineNum=line[0],
            rule=best_match["name"],
            value=token,
            file_name=file_name,
            entropy=entropy,
            context=line[2],
            uri_detected=uri_detected
        )

    def detect_sensitive(self, line: Tuple[int | None, str, List], file_name, commit):
        hits = []

        for name, rx, conf in self.sensitive_patterns_list:
            match = match_line(line[1], rx, name, conf)
            if match:
                hits.append(match)

        best_match = select_best_match(hits)


        if best_match is None:
            return None

        token = best_match["token"]

        _id = self.last_id
        self.last_id += 1

        return build_sensitive(
            lineNum=line[0],
            _id=_id,
            rule=best_match["name"],
            value=token,
            file_name=file_name,
            commit=commit,
            context=line[2],
        )