#!/usr/bin/env python3
"""
R3: OWASP Vulnerability Graph
Deep OWASP + CWE pattern scanner with language-aware analysis.
Provides richer context than the grep-based hook for command/agent use.

Usage:
    python3 vuln-scanner.py <file_to_scan> [patterns_json]
"""

import json
import os
import re
import sys


# Map file extensions to language identifiers
EXTENSION_MAP = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".py": "python", ".pyw": "python",
    ".java": "java",
    ".rb": "ruby", ".rake": "ruby",
    ".php": "php",
    ".go": "go",
    ".rs": "rust",
}

# OWASP Top 10 2021 category names
OWASP_NAMES = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable Components",
    "A07:2021": "Auth Failures",
    "A08:2021": "Software/Data Integrity",
    "A09:2021": "Logging Failures",
    "A10:2021": "SSRF",
}


def detect_language(file_path):
    """Detect programming language from file extension."""
    _, ext = os.path.splitext(file_path)
    return EXTENSION_MAP.get(ext.lower())


def load_patterns(patterns_path):
    """Load vulnerability patterns from JSON."""
    with open(patterns_path, "r", encoding="utf-8") as f:
        return json.load(f)


def is_in_comment(line, language):
    """Heuristic check if a line is a comment."""
    stripped = line.strip()
    if language in ("javascript", "typescript", "java", "go", "rust"):
        return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")
    elif language == "python":
        return stripped.startswith("#")
    elif language == "ruby":
        return stripped.startswith("#")
    elif language == "php":
        return stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*")
    return False


def scan_file(file_path, patterns_path=None):
    """Scan a file for vulnerability patterns with language awareness."""
    language = detect_language(file_path)
    if language is None:
        return []

    if patterns_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        patterns_path = os.path.join(script_dir, "..", "patterns", "vulns.json")

    patterns = load_patterns(patterns_path)

    # Filter patterns by language
    applicable = [p for p in patterns if language in p.get("language", [])]
    if not applicable:
        return []

    # Read file
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return []

    findings = []

    for line_num, line in enumerate(lines, 1):
        if line_num > 2000:
            break

        # Skip comments (reduce false positives)
        if is_in_comment(line, language):
            continue

        for pattern_info in applicable:
            try:
                if re.search(pattern_info["pattern"], line):
                    # Get surrounding context (3 lines before and after)
                    ctx_start = max(0, line_num - 4)
                    ctx_end = min(len(lines), line_num + 3)
                    context = [l.rstrip() for l in lines[ctx_start:ctx_end]]

                    owasp_id = pattern_info.get("owasp", "")
                    owasp_name = OWASP_NAMES.get(owasp_id, "")

                    findings.append({
                        "line": line_num,
                        "vuln_id": pattern_info["id"],
                        "cwe": pattern_info["cwe"],
                        "owasp": owasp_id,
                        "owasp_name": owasp_name,
                        "severity": pattern_info["severity"],
                        "category": pattern_info["category"],
                        "description": pattern_info["description"],
                        "language": language,
                        "context": context,
                    })
            except re.error:
                continue  # Skip invalid regex patterns

    return findings


USAGE = "Usage: vuln-scanner.py <file_to_scan> [patterns_json]"


def main():
    if len(sys.argv) < 2:
        print(USAGE, file=sys.stderr)
        sys.exit(2)

    file_path = sys.argv[1]
    patterns_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.isfile(file_path):
        print(f"vuln-scanner.py: input file not found or not a regular file: {file_path}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        sys.exit(2)
    if not os.access(file_path, os.R_OK):
        print(f"vuln-scanner.py: input file not readable: {file_path}", file=sys.stderr)
        sys.exit(2)
    if patterns_path is not None and not os.path.isfile(patterns_path):
        print(f"vuln-scanner.py: patterns JSON not found: {patterns_path}", file=sys.stderr)
        sys.exit(2)

    findings = scan_file(file_path, patterns_path)
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
