#!/usr/bin/env python3
"""
R6: Phantom Dependency Detection
Detects AI-hallucinated package names (slopsquatting) and typosquats.
Cross-references imports against known package registries.

Usage:
    python3 supply-chain.py <project_root> [slopsquatting_json]
"""

import json
import os
import re
import sys


def levenshtein_distance(s1, s2):
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)

    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def extract_npm_imports(file_path):
    """Extract package names from JavaScript/TypeScript files."""
    packages = set()
    import_pattern = re.compile(
        r'''(?:import\s+.*?from\s+|require\s*\(\s*)['"]([^'"./][^'"]*?)['"]'''
    )

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                for match in import_pattern.finditer(line):
                    pkg = match.group(1)
                    # Handle scoped packages: @scope/name → @scope/name
                    if "/" in pkg and not pkg.startswith("@"):
                        pkg = pkg.split("/")[0]
                    elif pkg.startswith("@") and "/" in pkg:
                        parts = pkg.split("/")
                        pkg = "/".join(parts[:2])
                    packages.add(pkg)
    except (OSError, IOError):
        pass

    return packages


def extract_python_imports(file_path):
    """Extract package names from Python files."""
    packages = set()
    import_pattern = re.compile(r'^(?:import|from)\s+(\w+)')

    # Python stdlib modules to exclude
    stdlib = {
        "os", "sys", "re", "json", "math", "time", "datetime", "pathlib",
        "collections", "itertools", "functools", "typing", "abc", "io",
        "hashlib", "hmac", "secrets", "random", "string", "textwrap",
        "subprocess", "shutil", "glob", "tempfile", "logging", "unittest",
        "argparse", "configparser", "csv", "sqlite3", "http", "urllib",
        "socket", "threading", "multiprocessing", "queue", "struct",
        "enum", "dataclasses", "contextlib", "copy", "pprint", "dis",
        "ast", "inspect", "importlib", "pkgutil", "warnings", "traceback",
        "base64", "binascii", "codecs", "html", "xml", "email",
    }

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                match = import_pattern.match(line.strip())
                if match:
                    pkg = match.group(1)
                    if pkg not in stdlib and not pkg.startswith("_"):
                        packages.add(pkg)
    except (OSError, IOError):
        pass

    return packages


def parse_lockfile_packages(project_root):
    """Extract known packages from lockfiles."""
    known = set()

    # package-lock.json
    lock_path = os.path.join(project_root, "package-lock.json")
    if os.path.exists(lock_path):
        try:
            with open(lock_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for pkg in data.get("packages", {}):
                name = pkg.lstrip("node_modules/")
                if name:
                    known.add(name)
            for pkg in data.get("dependencies", {}):
                known.add(pkg)
        except (json.JSONDecodeError, OSError):
            pass

    # requirements.txt
    req_path = os.path.join(project_root, "requirements.txt")
    if os.path.exists(req_path):
        try:
            with open(req_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        pkg = re.split(r'[>=<!\[]', line)[0].strip()
                        if pkg:
                            known.add(pkg.lower())
        except (OSError, IOError):
            pass

    return known


def load_slopsquatting_db(db_path):
    """Load slopsquatting database."""
    with open(db_path, "r", encoding="utf-8") as f:
        return json.load(f)


def check_package(pkg_name, ecosystem, slopsquat_db):
    """Check a package name against the slopsquatting database."""
    findings = []
    eco_data = slopsquat_db.get("ecosystems", {}).get(ecosystem, {})

    # Check known hallucinated packages
    for entry in eco_data.get("hallucinated", []):
        if entry["name"] == pkg_name:
            findings.append({
                "package": pkg_name,
                "ecosystem": ecosystem,
                "type": "hallucinated",
                "reason": entry["reason"],
                "real_alternative": entry.get("real_alternative"),
                "severity": "high",
                "confidence": 1.0,
            })
            return findings

    # Check known typosquats
    for entry in eco_data.get("typosquats", []):
        if entry["name"] == pkg_name:
            findings.append({
                "package": pkg_name,
                "ecosystem": ecosystem,
                "type": "typosquat",
                "target": entry["target"],
                "distance": entry["distance"],
                "severity": "high",
                "confidence": 1.0,
            })
            return findings

    # Check Levenshtein distance to known typosquat targets
    rules = slopsquat_db.get("detection_rules", {})
    max_dist = rules.get("max_levenshtein_distance", 2)

    for entry in eco_data.get("typosquats", []):
        target = entry["target"]
        dist = levenshtein_distance(pkg_name, target)
        if 0 < dist <= max_dist:
            findings.append({
                "package": pkg_name,
                "ecosystem": ecosystem,
                "type": "potential_typosquat",
                "similar_to": target,
                "distance": dist,
                "severity": "medium",
                "confidence": round(1.0 - (dist / max(len(pkg_name), len(target))), 2),
            })

    return findings


def scan_project(project_root, db_path=None):
    """Scan a project for phantom dependencies."""
    if db_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(script_dir, "..", "patterns", "slopsquatting.json")

    slopsquat_db = load_slopsquatting_db(db_path)
    lockfile_packages = parse_lockfile_packages(project_root)

    all_findings = []

    # Scan JavaScript/TypeScript files
    for root, _dirs, files in os.walk(project_root):
        # Skip node_modules, .git, etc.
        if any(skip in root for skip in ["node_modules", ".git", "__pycache__", "venv"]):
            continue

        for fname in files:
            fpath = os.path.join(root, fname)

            if fname.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
                imports = extract_npm_imports(fpath)
                for pkg in imports:
                    if pkg not in lockfile_packages:
                        findings = check_package(pkg, "npm", slopsquat_db)
                        for f in findings:
                            f["source_file"] = os.path.relpath(fpath, project_root)
                        all_findings.extend(findings)

            elif fname.endswith((".py", ".pyw")):
                imports = extract_python_imports(fpath)
                for pkg in imports:
                    if pkg.lower() not in lockfile_packages:
                        findings = check_package(pkg, "pypi", slopsquat_db)
                        for f in findings:
                            f["source_file"] = os.path.relpath(fpath, project_root)
                        all_findings.extend(findings)

    return all_findings


USAGE = "Usage: supply-chain.py <project_root> [slopsquatting_json]"


def main():
    if len(sys.argv) < 2:
        print(USAGE, file=sys.stderr)
        sys.exit(2)

    project_root = sys.argv[1]
    db_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.isdir(project_root):
        print(f"supply-chain.py: project_root not found or not a directory: {project_root}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        sys.exit(2)
    if db_path is not None and not os.path.isfile(db_path):
        print(f"supply-chain.py: slopsquatting JSON not found: {db_path}", file=sys.stderr)
        sys.exit(2)

    findings = scan_project(project_root, db_path)
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
