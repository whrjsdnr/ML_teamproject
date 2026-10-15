"""FQDN-only experimental lexical features; no DNS9 compatibility claim."""

import math
import re
from collections import Counter

from ml.verified_producers.contracts import FeatureVector, vector


def dns_features(fqdn: str, *, source_origin: str) -> FeatureVector:
    if source_origin not in {
        "EXPLICIT_FQDN_FIXTURE",
        "RAW_LABELED_FQDN",
        "NATIVE_DNS_QUERY",
    }:
        raise ValueError("UNKNOWN_SOURCE_ORIGIN")
    if not isinstance(fqdn, str) or not 1 <= len(fqdn) <= 254 or not fqdn.isascii():
        raise ValueError("INVALID_FQDN")
    canonical = fqdn.removesuffix(".").lower()
    if not canonical or len(canonical) > 253:
        raise ValueError("INVALID_FQDN_LENGTH")
    labels = canonical.split(".")
    if any(not re.fullmatch(r"[a-z0-9_-]{1,63}", label) for label in labels):
        raise ValueError("INVALID_FQDN_LABEL")
    population = "".join(labels)
    size = len(population)
    counts = Counter(population)
    entropy = -math.fsum(
        (count / size) * math.log2(count / size) for count in counts.values()
    )
    values = (
        len(canonical),
        len(labels),
        max(map(len, labels)),
        size / len(labels),
        sum("0" <= c <= "9" for c in population) / size,
        sum(c in "_-" for c in population) / size,
        entropy,
    )
    # Bind original spelling, even when normalization yields the same feature vector.
    return vector(
        "dns",
        {"fqdn": fqdn, "source_origin": source_origin},
        values,
        source_origin,
        "UNATTESTED",
    )
