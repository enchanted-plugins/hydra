#!/usr/bin/env python3
"""
R2: Shannon Entropy Analysis
Detects high-entropy strings that look like secrets but don't match known patterns.
Flag if H(s) > 4.5 bits/char and |s| > 20.

Usage:
    python3 entropy-analyzer.py <file_to_scan>
"""

import json
import math
import os
import re
import sys


# Strings matching this regex are candidates for entropy analysis
HIGH_ENTROPY_PATTERN = re.compile(r'[a-zA-Z0-9+/=_\-]{20,}')

# Exclude known false positives
EXCLUDE_PATTERNS = [
    re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),  # UUID
    re.compile(r'^[0-9a-f]{40}$'),   # SHA-1 hash (common in lock files)
    re.compile(r'^[0-9a-f]{64}$'),   # SHA-256 hash
    re.compile(r'^[0-9a-f]{32}$'),   # MD5 hash
    re.compile(r'^[A-Za-z]+$'),       # Pure alphabetic (likely a word/variable)
    re.compile(r'^[0-9]+$'),          # Pure numeric
    re.compile(r'^/{1,2}[a-zA-Z]'),   # File paths
    re.compile(r'^https?://'),         # URLs
    re.compile(r'^data:'),             # Data URIs
]


def shannon_entropy(s):
    """
    Compute Shannon entropy of a string.
    H(s) = -sum(p(c) * log2(p(c))) for each character c in s
    """
    if not s:
        return 0.0

    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1

    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def mask_value(value, prefix_len=4, suffix_len=4):
    """Mask a value for safe logging."""
    if len(value) < prefix_len + suffix_len + 3:
        return "[REDACTED]"
    return f"{value[:prefix_len]}...{value[-suffix_len:]}"


def is_excluded(s):
    """Check if a string matches known false-positive patterns."""
    for pattern in EXCLUDE_PATTERNS:
        if pattern.match(s):
            return True
    return False


def analyze_file(file_path, threshold=4.5, min_length=20):
    """Scan a file for high-entropy strings."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return []

    findings = []

    for line_num, line in enumerate(lines, 1):
        if line_num > 2000:
            break

        # Find candidate strings
        for match in HIGH_ENTROPY_PATTERN.finditer(line):
            candidate = match.group()

            if len(candidate) < min_length:
                continue

            if is_excluded(candidate):
                continue

            entropy = shannon_entropy(candidate)

            if entropy > threshold:
                findings.append({
                    "line": line_num,
                    "column": match.start() + 1,
                    "entropy": round(entropy, 3),
                    "length": len(candidate),
                    "preview": mask_value(candidate),
                    "severity": "high" if entropy > 5.0 else "medium",
                })

    return findings


USAGE = "Usage: entropy-analyzer.py <file_to_scan> [threshold] [min_length]"


def main():
    if len(sys.argv) < 2:
        print(USAGE, file=sys.stderr)
        sys.exit(2)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print(f"entropy-analyzer.py: input file not found or not a regular file: {file_path}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        sys.exit(2)
    if not os.access(file_path, os.R_OK):
        print(f"entropy-analyzer.py: input file not readable: {file_path}", file=sys.stderr)
        sys.exit(2)

    try:
        threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 4.5
        min_length = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    except ValueError:
        print("entropy-analyzer.py: threshold must be float, min_length must be int", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        sys.exit(2)

    findings = analyze_file(file_path, threshold, min_length)
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
