from __future__ import annotations

import math


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte. Empty input is 0. Random bytes sit near 8."""

    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy
