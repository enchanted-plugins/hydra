#!/usr/bin/env python3
"""Corpus language-fidelity tests.

A rule that carries `"language": ["go"]` is making a claim: "I can detect
this defect in Go." Before this test existed, 11 of 19 Go-tagged rules could
not match idiomatic vulnerable Go at all — several contained only Python,
Java, C# or JavaScript syntax, and the credential rules required `=` so Go's
`:=` declaration form silently evaded them.

This test makes that class of drift impossible to reintroduce: every rule
tagged for a language must either

  * match a real, idiomatic, vulnerable line for that language, or
  * be explicitly listed as `taint_bound` with a stated reason.

It also pins false positives: no rule may fire on the safe lookalikes.

Run: python3 tests/shared/test-corpus-language-fidelity.py
"""

import glob
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
PATTERNS = os.path.join(ROOT, "shared", "patterns", "vulns.json")
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "language-fidelity")


def load_patterns():
    with open(PATTERNS, encoding="utf-8") as fh:
        return json.load(fh)


def load_fixtures():
    out = {}
    for path in sorted(glob.glob(os.path.join(FIXTURES, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        out[data["language"]] = data
    return out


class TestLanguageFidelity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_patterns()
        cls.fixtures = load_fixtures()
        assert cls.fixtures, "no language-fidelity fixtures found"

    def test_every_tagged_rule_is_accounted_for(self):
        """No rule may claim a language without a proving case or a reason."""
        for lang, fx in self.fixtures.items():
            tagged = [p for p in self.patterns if lang in p.get("language", [])]
            known = set(fx["positive"]) | set(fx["taint_bound"])
            missing = sorted({p["id"] for p in tagged} - known)
            self.assertEqual(
                missing, [],
                f"[{lang}] rules claim this language but have neither a "
                f"proving case nor a taint_bound reason: {missing}",
            )

    def test_positive_cases_actually_fire(self):
        """A claimed language must be a language the regex can match."""
        by_id = {p["id"]: p for p in self.patterns}
        for lang, fx in self.fixtures.items():
            for rid, line in fx["positive"].items():
                with self.subTest(language=lang, rule=rid):
                    self.assertIn(rid, by_id, f"unknown rule id {rid}")
                    self.assertRegex(
                        line, by_id[rid]["pattern"],
                        f"[{lang}] rule {rid} claims this language but does "
                        f"not match its own idiomatic vulnerable form",
                    )

    def test_no_false_positives_on_safe_lookalikes(self):
        """Safe idiomatic code must not trip any rule for that language."""
        for lang, fx in self.fixtures.items():
            tagged = [p for p in self.patterns if lang in p.get("language", [])]
            for line in fx["negative"]:
                hits = []
                for p in tagged:
                    try:
                        if re.search(p["pattern"], line):
                            hits.append(p["id"])
                    except re.error:
                        self.fail(f"rule {p['id']} has an invalid regex")
                with self.subTest(language=lang, line=line.strip()[:48]):
                    self.assertEqual(
                        hits, [], f"[{lang}] false positive on safe code")

    def test_all_patterns_compile(self):
        for p in self.patterns:
            with self.subTest(rule=p["id"]):
                try:
                    re.compile(p["pattern"])
                except re.error as exc:
                    self.fail(f"{p['id']}: invalid regex: {exc}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
