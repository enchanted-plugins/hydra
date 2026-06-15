#!/usr/bin/env python3
"""
R1: Aho-Corasick Pattern Engine
Stdlib-only trie with failure links for O(n+m+z) multi-pattern matching.
Used for batch/deep scanning — hooks use grep for real-time speed.

Usage:
    python3 pattern-engine.py <file_to_scan> [patterns_json]
"""

import json
import os
import sys
from collections import deque


class AhoCorasickAutomaton:
    """Aho-Corasick automaton for multi-pattern string matching."""

    def __init__(self):
        self.goto = [{}]       # goto function: state -> char -> state
        self.failure = [0]     # failure function: state -> state
        self.output = [[]]     # output function: state -> list of pattern IDs
        self.num_states = 1

    def _add_state(self):
        self.goto.append({})
        self.failure.append(0)
        self.output.append([])
        state = self.num_states
        self.num_states += 1
        return state

    def add_pattern(self, pattern_str, pattern_id):
        """Add a pattern string with its identifier to the automaton."""
        state = 0
        for char in pattern_str:
            if char not in self.goto[state]:
                self.goto[state][char] = self._add_state()
            state = self.goto[state][char]
        self.output[state].append(pattern_id)

    def build(self):
        """Build failure links using BFS."""
        queue = deque()

        # Initialize failure for depth-1 states
        for char, next_state in self.goto[0].items():
            self.failure[next_state] = 0
            queue.append(next_state)

        # BFS to build failure links
        while queue:
            current = queue.popleft()
            for char, next_state in self.goto[current].items():
                queue.append(next_state)

                # Follow failure links to find longest proper suffix
                fallback = self.failure[current]
                while fallback != 0 and char not in self.goto[fallback]:
                    fallback = self.failure[fallback]

                self.failure[next_state] = self.goto[fallback].get(char, 0)
                if self.failure[next_state] == next_state:
                    self.failure[next_state] = 0

                # Merge output from failure state
                self.output[next_state] = (
                    self.output[next_state] + self.output[self.failure[next_state]]
                )

    def search(self, text):
        """Search text for all patterns. Yields (position, pattern_id) tuples."""
        state = 0
        for i, char in enumerate(text):
            while state != 0 and char not in self.goto[state]:
                state = self.failure[state]
            state = self.goto[state].get(char, 0)

            for pattern_id in self.output[state]:
                yield (i, pattern_id)


def mask_secret(value, prefix_len=4, suffix_len=4):
    """Mask a secret value — show only first N and last N chars."""
    if len(value) < prefix_len + suffix_len + 3:
        return "[REDACTED]"
    return f"{value[:prefix_len]}...{value[-suffix_len:]}"


def load_patterns(patterns_path):
    """Load secret patterns from JSON file."""
    with open(patterns_path, "r", encoding="utf-8") as f:
        return json.load(f)


def scan_file(file_path, patterns_path=None):
    """Scan a file for secret patterns using Aho-Corasick."""
    if patterns_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        patterns_path = os.path.join(script_dir, "..", "patterns", "secrets.json")

    patterns = load_patterns(patterns_path)

    # Build automaton with literal prefixes from patterns
    automaton = AhoCorasickAutomaton()
    pattern_map = {}

    for pat in patterns:
        # Extract a literal prefix for Aho-Corasick (before any regex metacharacter)
        literal = ""
        for ch in pat["pattern"]:
            if ch in r"\.[](){}*+?|^$":
                break
            literal += ch

        if len(literal) >= 4:  # Only add patterns with meaningful literal prefix
            automaton.add_pattern(literal, pat["id"])
            pattern_map[pat["id"]] = pat

    automaton.build()

    # Read file
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return []

    findings = []
    for line_num, line in enumerate(lines, 1):
        # Cap at 2000 lines for performance
        if line_num > 2000:
            break

        matches = list(automaton.search(line))
        seen_patterns = set()

        for pos, pattern_id in matches:
            if pattern_id in seen_patterns:
                continue
            seen_patterns.add(pattern_id)

            pat_info = pattern_map.get(pattern_id, {})

            # Extract the matched region for masking
            start = max(0, pos - 40)
            end = min(len(line), pos + 1)
            matched_text = line[start:end].strip()

            findings.append({
                "line": line_num,
                "pattern_id": pattern_id,
                "severity": pat_info.get("severity", "medium"),
                "category": pat_info.get("category", "unknown"),
                "description": pat_info.get("description", ""),
                "masked": mask_secret(matched_text),
            })

    return findings


USAGE = "Usage: pattern-engine.py <file_to_scan> [patterns_json]"


def main():
    if len(sys.argv) < 2:
        print(USAGE, file=sys.stderr)
        sys.exit(2)

    file_path = sys.argv[1]
    patterns_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.isfile(file_path):
        print(f"pattern-engine.py: input file not found or not a regular file: {file_path}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        sys.exit(2)
    if not os.access(file_path, os.R_OK):
        print(f"pattern-engine.py: input file not readable: {file_path}", file=sys.stderr)
        sys.exit(2)
    if patterns_path is not None and not os.path.isfile(patterns_path):
        print(f"pattern-engine.py: patterns JSON not found: {patterns_path}", file=sys.stderr)
        sys.exit(2)

    findings = scan_file(file_path, patterns_path)
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
