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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import coverage as cov  # noqa: E402

# Hard cap on how many lines of a file we scan. Kept for performance, but
# NEVER silent: exceeding it sets `truncated` on every coverage entry.
MAX_LINES = 2000

# Taint tokens the web-shaped rules require to appear on the SAME line as the
# sink. Any pattern containing one is shape-bound to a web handler: it cannot
# see taint arriving from argv, env, a config file, or another function. We
# detect this by inspecting the regex rather than hardcoding a rule list, so
# the coverage claim cannot drift away from the corpus.
_HTTP_TAINT_TOKENS = (
    r"r\.(?:URL|Form|PostForm)",
    r"r\.Header\.Get",
    r"mux\.Vars",
    r"c\.(?:Param|Query)",
    "req.body", "req.query", "req.params",
    "request.args", "request.form",
)

_NON_WEB_SHAPES = [
    "argv", "environment", "config-file", "stdin",
    "function-parameter", "cross-line", "cross-function",
]


def _is_shape_bound(pattern_src):
    """True if this regex only fires when an HTTP taint token is on the line."""
    return any(tok in pattern_src for tok in _HTTP_TAINT_TOKENS)


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
        if line_num > MAX_LINES:
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


def build_coverage(file_path, patterns_path=None):
    """Derive the coverage claim for this file WITHOUT relying on findings.

    Coverage is a statement about capability, not about results, so it is
    computed from the language, the corpus and the file size alone.
    """
    language = detect_language(file_path)

    try:
        n_lines = sum(1 for _ in open(file_path, "r", encoding="utf-8",
                                      errors="replace"))
    except (OSError, IOError):
        n_lines = None

    if language is None:
        ext = os.path.splitext(file_path)[1].lower() or "(none)"
        entry = cov.CoverageEntry(
            cls="*", engine="hydra-regex", depth=cov.PATTERN,
            status=cov.UNSUPPORTED,
            notes=f"no rules for extension {ext}; file was not analysed at all",
        )
        return language, n_lines, 0, [entry]

    if patterns_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        patterns_path = os.path.join(script_dir, "..", "patterns", "vulns.json")

    try:
        patterns = load_patterns(patterns_path)
    except (OSError, IOError, ValueError) as exc:
        entry = cov.CoverageEntry(
            cls="*", engine="hydra-regex", depth=cov.PATTERN,
            status=cov.UNAVAILABLE,
            notes=f"pattern corpus unreadable: {exc}",
        )
        return language, n_lines, 0, [entry]

    applicable = [p for p in patterns if language in p.get("language", [])]
    truncated = bool(n_lines and n_lines > MAX_LINES)
    analyzed = min(n_lines, MAX_LINES) if n_lines else None

    if not applicable:
        entry = cov.CoverageEntry(
            cls="*", engine="hydra-regex", depth=cov.PATTERN,
            status=cov.UNSUPPORTED, truncated=truncated,
            notes=f"corpus has no {language} rules",
        )
        return language, n_lines, analyzed, [entry]

    # Group by defect class and decide each class's honest status.
    by_class = {}
    for p in applicable:
        by_class.setdefault(p.get("category", "uncategorised"), []).append(p)

    entries = []
    for cls, pats in sorted(by_class.items()):
        shape_bound = any(_is_shape_bound(p["pattern"]) for p in pats)
        # A line-local regex engine is NEVER 'complete' for a dataflow class:
        # it cannot follow taint across lines or functions. The most it can
        # honestly claim is 'partial'.
        unsupported = list(_NON_WEB_SHAPES)
        supported = ["same-line literal match"]
        if shape_bound:
            supported = ["http-handler taint on the same line as the sink"]
        entries.append(cov.CoverageEntry(
            cls=cls, engine="hydra-regex", depth=cov.PATTERN,
            status=cov.DEGRADED if truncated else cov.PARTIAL,
            shapes_supported=supported,
            shapes_unsupported=unsupported,
            truncated=truncated,
            notes=(
                f"{len(pats)} single-line regex rule(s); "
                + ("requires an HTTP taint token on the sink line"
                   if shape_bound else "literal/token match only")
            ),
        ))

    return language, n_lines, analyzed, entries


def scan_file_report(file_path, patterns_path=None):
    """Full analysis report: findings AND coverage."""
    findings = scan_file(file_path, patterns_path)
    language, n_lines, analyzed, entries = build_coverage(
        file_path, patterns_path)
    return cov.build_report(
        tool="hydra-vuln-scanner",
        target_path=file_path,
        language=language,
        findings=findings,
        coverage=entries,
        lines_total=n_lines,
        lines_analyzed=analyzed,
    )


USAGE = ("Usage: vuln-scanner.py <file_to_scan> [patterns_json] "
         "[--findings-only]")


def main():
    argv = [a for a in sys.argv[1:] if a != "--findings-only"]
    findings_only = "--findings-only" in sys.argv

    if not argv:
        print(USAGE, file=sys.stderr)
        sys.exit(2)

    file_path = argv[0]
    patterns_path = argv[1] if len(argv) > 1 else None

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

    if findings_only:
        # Legacy shape: a bare findings array. Retained for existing
        # consumers, but it CANNOT express coverage, so anything reading it
        # must not treat an empty array as assurance.
        print(json.dumps(scan_file(file_path, patterns_path), indent=2))
        return

    report = scan_file_report(file_path, patterns_path)
    print(json.dumps(report, indent=2))
    # The operator-facing line goes to stderr so it never corrupts the JSON.
    print(cov.human_summary(report), file=sys.stderr)


if __name__ == "__main__":
    main()
