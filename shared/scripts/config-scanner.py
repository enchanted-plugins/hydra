#!/usr/bin/env python3
"""
R5: Config Poisoning Detection (deep analysis)
Parses config files, decodes base64 payloads, detects obfuscated commands.
Richer analysis than the bash hook for command/agent use.

Usage:
    python3 config-scanner.py <project_root> [patterns_json]
"""

import base64
import json
import os
import re
import sys


def load_patterns(patterns_path):
    """Load config attack patterns."""
    with open(patterns_path, "r", encoding="utf-8") as f:
        return json.load(f)


def decode_base64_payloads(content):
    """Find and decode base64-encoded payloads in content."""
    decoded_parts = []
    b64_pattern = re.compile(r'[A-Za-z0-9+/=]{40,}')

    for match in b64_pattern.finditer(content):
        candidate = match.group()
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
            # Check if decoded content looks suspicious
            suspicious_keywords = ["curl", "wget", "bash", "sh", "python", "eval",
                                   "exec", "nc", "ncat", "reverse", "/dev/tcp"]
            if any(kw in decoded.lower() for kw in suspicious_keywords):
                decoded_parts.append({
                    "encoded": candidate[:20] + "...",
                    "decoded_preview": decoded[:100],
                    "position": match.start(),
                })
        except Exception:
            continue

    return decoded_parts


def check_hidden_unicode(content):
    """Detect hidden Unicode characters used for prompt injection."""
    hidden_chars = {
        '\u200b': 'ZERO WIDTH SPACE',
        '\u200c': 'ZERO WIDTH NON-JOINER',
        '\u200d': 'ZERO WIDTH JOINER',
        '\u2060': 'WORD JOINER',
        '\ufeff': 'ZERO WIDTH NO-BREAK SPACE',
        '\u00ad': 'SOFT HYPHEN',
        '\u200e': 'LEFT-TO-RIGHT MARK',
        '\u200f': 'RIGHT-TO-LEFT MARK',
        '\u202a': 'LEFT-TO-RIGHT EMBEDDING',
        '\u202b': 'RIGHT-TO-LEFT EMBEDDING',
        '\u202c': 'POP DIRECTIONAL FORMATTING',
    }

    findings = []
    for i, char in enumerate(content):
        if char in hidden_chars:
            # Find line number
            line_num = content[:i].count('\n') + 1
            findings.append({
                "char": repr(char),
                "name": hidden_chars[char],
                "line": line_num,
                "position": i,
            })

    return findings


def analyze_json_config(file_path, content):
    """Deep analysis of JSON config files."""
    findings = []

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return findings

    def walk(obj, path=""):
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                walk(value, current_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{path}[{i}]")
        elif isinstance(obj, str):
            # Check for suspicious command patterns in string values
            suspicious = ["curl", "wget", "bash -c", "sh -c", "python -c",
                          "eval(", "exec(", "/dev/tcp", "nc -e"]
            for sus in suspicious:
                if sus in obj.lower():
                    findings.append({
                        "path": path,
                        "value_preview": obj[:80] + ("..." if len(obj) > 80 else ""),
                        "suspicious_pattern": sus,
                        "severity": "critical",
                    })

    walk(data)
    return findings


def scan_project(project_root, patterns_path=None):
    """Scan project for malicious config files."""
    if patterns_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        patterns_path = os.path.join(script_dir, "..", "patterns", "config-attacks.json")

    patterns = load_patterns(patterns_path)
    all_findings = []

    for pattern_info in patterns:
        file_pattern = pattern_info["file_pattern"]

        # Handle glob patterns
        if "*" in file_pattern:
            import glob
            matches = glob.glob(os.path.join(project_root, file_pattern), recursive=True)
        else:
            candidate = os.path.join(project_root, file_pattern)
            matches = [candidate] if os.path.exists(candidate) else []

        for config_file in matches:
            if not os.path.isfile(config_file):
                continue

            try:
                with open(config_file, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            rel_path = os.path.relpath(config_file, project_root)

            # Pattern match
            try:
                if re.search(pattern_info["pattern"], content):
                    finding = {
                        "file": rel_path,
                        "attack_id": pattern_info["id"],
                        "check": pattern_info["check"],
                        "cve": pattern_info.get("cve"),
                        "severity": pattern_info["severity"],
                        "description": pattern_info["description"],
                    }

                    # Deep analysis for JSON configs
                    if config_file.endswith(".json"):
                        json_findings = analyze_json_config(config_file, content)
                        if json_findings:
                            finding["json_analysis"] = json_findings

                    # Check for base64-encoded payloads
                    b64_findings = decode_base64_payloads(content)
                    if b64_findings:
                        finding["base64_payloads"] = b64_findings

                    # Check for hidden Unicode
                    unicode_findings = check_hidden_unicode(content)
                    if unicode_findings:
                        finding["hidden_unicode"] = unicode_findings

                    all_findings.append(finding)
            except re.error:
                continue

    return all_findings


USAGE = "Usage: config-scanner.py <project_root> [patterns_json]"


def main():
    if len(sys.argv) < 2:
        print(USAGE, file=sys.stderr)
        sys.exit(2)

    project_root = sys.argv[1]
    patterns_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.isdir(project_root):
        print(f"config-scanner.py: project_root not found or not a directory: {project_root}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        sys.exit(2)
    if patterns_path is not None and not os.path.isfile(patterns_path):
        print(f"config-scanner.py: patterns JSON not found: {patterns_path}", file=sys.stderr)
        sys.exit(2)

    findings = scan_project(project_root, patterns_path)
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
