import json, base64
import re
import zlib
from urllib.parse import urlsplit

# Words/substrings to detect placeholders, examples and reduce LLM-usage
_EXAMPLE_VAL_SUBSTRINGS = (
    "EXAMPLE","SAMPLE","DUMMY","FAKE","TEST","PLACEHOLDER","MOCK","INVALID","NOTREAL"
)
_EXAMPLE_LINE_WORDS = tuple(w.lower() for w in _EXAMPLE_VAL_SUBSTRINGS) + (
    "stub","demo","template"
)
_EXAMPLE_PATH_WORDS = ("example","examples","sample","samples","test","tests","mock","mocks","docs","readme", "demo")

# Regexes to detect words-like sequences
_WORDY = re.compile(r'[a-z]{5,}')
_CAMEL = re.compile(r'[A-Z][a-z]{3,}[A-Z][a-z]{2,}')

# Decode b64url
def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)

# Detecting JWT token by decoding all its parts and re-encoding
def detect_jwt(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3: return False
    if len(token) % 4 == 1:
        return False

    try:
        h_b = _b64url_decode(parts[0])
        p_b = _b64url_decode(parts[1])
        s_b = _b64url_decode(parts[2])

        if not (base64.urlsafe_b64encode(h_b).decode().rstrip('=') == parts[0] and
            base64.urlsafe_b64encode(p_b).decode().rstrip('=') == parts[1] and
            base64.urlsafe_b64encode(s_b).decode().rstrip('=') == parts[2]):
            return False
    except Exception:
        return False

    header = json.loads(h_b.decode('utf-8', 'ignore'))

    # Likely to be a JWT
    likely_jwt = (
        isinstance(header, dict) and "alg" in header
    )

    return likely_jwt

# Clean uri (maybe useful sometimes)
def _clean_uri(uri: str):
    while uri and uri[-1] in '.,;)]:}':
        uri = uri[:-1]

    uri = uri.lstrip('([{')
    return uri

# Check whether a line contains some placeholder/example indicators
def is_example_like(val: str, line: str, file_path: str) -> bool:
    v = val.upper()
    if any(word in v for word in _EXAMPLE_VAL_SUBSTRINGS):
        return True

    l = (line or "").lower()
    if any(word in l for word in _EXAMPLE_LINE_WORDS):
        return True

    p = (file_path or "").lower()
    if any(part in p for part in _EXAMPLE_PATH_WORDS):
        return True

    return False

# Detect whether some token is an uri and contains potentially dangerous credentials
def detect_dangerous_uri(uri: str):
    uri_text = _clean_uri(uri)
    try:
        u = urlsplit(uri_text)
        if not u.scheme or not u.netloc:
            return False

        has_user = bool(u.username)
        has_pass = u.password is not None
        has_creds = has_user and has_pass

        if has_creds:
            return True

        return False
    except Exception:
        return False

# Calculate compression-ratio of some string to identify wordy-structure
def compression_ratio(token: str) -> float:
    if not token: return 1.0
    b = token.encode('utf-8','ignore')
    if len(b) < 16: return 1.0
    return len(zlib.compress(b, 9)) / len(b)

# Helper function which is a part of identifying whether a LLM should be engaged
def wordy_or_camel(s: str) -> bool:
    return bool(_WORDY.search(s) or _CAMEL.search(s))
