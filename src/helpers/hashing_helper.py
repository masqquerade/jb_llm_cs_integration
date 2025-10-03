import hashlib
import hmac

def _normalize(value: str) -> bytes:
    return value.strip().strip('"').strip("'").encode("utf-8", "ignore")

def secret_fingerprint(secret: str) -> str:
    b = _normalize(secret)
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()[:16]

def same_fingerprint(s1: str, s2: str) -> bool:
    sf1 = secret_fingerprint(s1)
    sf2 = secret_fingerprint(s2)

    return hmac.compare_digest(sf1, sf2)