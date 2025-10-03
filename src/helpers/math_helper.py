import math
from collections import Counter

# Calculate Shannon Entropy for some string
def shannon_entropy(s: str):
    if not s: return 0.0

    counts = Counter(s)
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())