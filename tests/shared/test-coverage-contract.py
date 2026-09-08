#!/usr/bin/env python3
"""Coverage-contract tests.

These encode the one law the analysis report exists to enforce:

    ZERO FINDINGS + INCOMPLETE COVERAGE MUST NEVER MEAN CLEAN.

Run: python3 tests/shared/test-coverage-contract.py
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SCANNER = os.path.join(ROOT, "shared", "scripts", "vuln-scanner.py")
sys.path.insert(0, os.path.join(ROOT, "shared", "scripts"))

import coverage as cov  # noqa: E402


def scan(path, *extra):
    proc = subprocess.run(
        [sys.executable, SCANNER, path, *extra],
        capture_output=True, text=True,
    )
    return json.loads(proc.stdout)


def write(tmp, name, body):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(body)
    return p


class TestFalseClean(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def test_empty_findings_on_go_is_not_clean(self):
        """A line-local regex engine can never claim 'clean' on a Go file."""
        p = write(self.tmp, "a.go", "package main\nfunc main() {}\n")
        r = scan(p)
        self.assertEqual(r["findings"], [])
        self.assertFalse(r["clean"])
        self.assertTrue(r["false_clean_risk"])
        self.assertEqual(r["analysis_status"], cov.PARTIAL)

    def test_unsupported_language_is_flagged_not_clean(self):
        """An extension with no rules must not look like a clean scan."""
        p = write(self.tmp, "a.c", 'char *pw = "hunter2";\nsystem(argv[1]);\n')
        r = scan(p)
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["analysis_status"], cov.UNSUPPORTED)
        self.assertTrue(r["false_clean_risk"])
        self.assertFalse(r["clean"])

    def test_truncation_is_never_silent(self):
        """Past the line cap the report must say so."""
        body = "package main\n" + ("// filler\n" * 2200)
        p = write(self.tmp, "big.go", body)
        r = scan(p)
        self.assertTrue(r["truncated"])
        self.assertEqual(r["analysis_status"], cov.DEGRADED)
        self.assertLess(r["target"]["lines_analyzed"], r["target"]["lines_total"])
        self.assertTrue(all(c["truncated"] for c in r["coverage"]))

    def test_shape_bound_rules_declare_their_blind_spots(self):
        """Injection coverage must admit it cannot see non-HTTP taint."""
        p = write(self.tmp, "a.go", "package main\nfunc main() {}\n")
        r = scan(p)
        inj = [c for c in r["coverage"] if c["class"] == "injection"]
        self.assertTrue(inj, "expected an injection coverage entry for Go")
        unsupported = set(inj[0]["shapes_unsupported"])
        for shape in ("config-file", "argv", "environment", "cross-function"):
            self.assertIn(shape, unsupported)

    def test_findings_still_reported(self):
        """The repair must not suppress real detections.

        Uses a real call site (md5.Sum(...)), not a bare `md5.New` reference:
        the rule deliberately requires a call form so that merely importing or
        referencing the symbol does not raise a finding.
        """
        p = write(self.tmp, "a.go",
                  'package main\n\nfunc h(data []byte) {\n'
                  '\tsum := md5.Sum(data)\n\t_ = sum\n}\n')
        r = scan(p)
        self.assertGreater(len(r["findings"]), 0)

    def test_bare_symbol_reference_does_not_fire(self):
        """A reference without a call must NOT be reported (precision)."""
        p = write(self.tmp, "a.go",
                  'package main\n\nimport "crypto/md5"\n\nvar _ = md5.New\n')
        r = scan(p)
        self.assertEqual(r["findings"], [])

    def test_legacy_mode_is_still_a_bare_array(self):
        """Existing consumers keep working via --findings-only."""
        p = write(self.tmp, "a.go", "package main\n")
        proc = subprocess.run(
            [sys.executable, SCANNER, p, "--findings-only"],
            capture_output=True, text=True,
        )
        self.assertIsInstance(json.loads(proc.stdout), list)


class TestWorstStatus(unittest.TestCase):
    def test_worst_status_wins(self):
        entries = [
            cov.CoverageEntry("a", "e", cov.PATTERN, cov.COMPLETE),
            cov.CoverageEntry("b", "e", cov.PATTERN, cov.UNAVAILABLE),
            cov.CoverageEntry("c", "e", cov.PATTERN, cov.PARTIAL),
        ]
        self.assertEqual(cov.worst_status(entries), cov.UNAVAILABLE)

    def test_no_coverage_is_unavailable(self):
        self.assertEqual(cov.worst_status([]), cov.UNAVAILABLE)

    def test_complete_and_untruncated_can_be_clean(self):
        entries = [cov.CoverageEntry("a", "e", cov.AST, cov.COMPLETE)]
        r = cov.build_report("t", "f", "go", [], entries)
        self.assertTrue(r["clean"])
        self.assertFalse(r["false_clean_risk"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
