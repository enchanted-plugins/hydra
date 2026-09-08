#!/usr/bin/env python3
"""PostToolUse hook coverage-contract tests.

The hook is a SEPARATE implementation from shared/scripts/vuln-scanner.py.
Repairing the scanner did not repair the hook, and the hook is the path that
actually fires during agent sessions - so its false-clean modes mattered more,
not less.

Before this change the hook emitted NOTHING when it:
  - met an extension it has no rules for
  - could not find the pattern corpus
  - truncated a file at the 2000-line cap
  - capped at 10 findings
  - found nothing at all

Silence was indistinguishable from "analysed and clean", and from "never ran".

These tests pin one coverage record per scan on every path, and pin that the
hook agrees with coverage.py about what `clean` means.

Run: python3 tests/vuln-detector/test-hook-coverage.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
HOOK = os.path.join(ROOT, "plugins", "vuln-detector", "hooks",
                    "post-tool-use", "detect-vuln.sh")
PLUGIN_ROOT = os.path.join(ROOT, "plugins", "vuln-detector")
STATE = os.path.join(PLUGIN_ROOT, "state", "audit.jsonl")

BASH = shutil.which("bash")


def tail_coverage(before_len):
    """Return coverage records appended since `before_len` bytes."""
    if not os.path.exists(STATE):
        return []
    with open(STATE, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(before_len)
        out = []
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if d.get("event") == "vuln_scan_coverage":
                out.append(d)
        return out


def state_size():
    return os.path.getsize(STATE) if os.path.exists(STATE) else 0


@unittest.skipIf(BASH is None, "bash not available")
class TestHookCoverage(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def run_hook(self, path):
        before = state_size()
        payload = json.dumps({"tool_name": "Write",
                              "tool_input": {"file_path": path}})
        env = dict(os.environ, CLAUDE_PLUGIN_ROOT=PLUGIN_ROOT)
        proc = subprocess.run([BASH, HOOK], input=payload, env=env,
                              capture_output=True, text=True, timeout=60)
        # Contract: the hook must never block, whatever happens.
        self.assertEqual(proc.returncode, 0, "hook must always exit 0")
        recs = tail_coverage(before)
        return proc, recs

    def write(self, name, body):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(body)
        return p

    def test_exactly_one_record_per_scan(self):
        p = self.write("a.go", "package main\n\nfunc main() {}\n")
        _, recs = self.run_hook(p)
        self.assertEqual(len(recs), 1, "expected exactly one coverage record")

    def test_zero_findings_still_emits_a_record(self):
        """The old hook logged nothing at all when it found nothing."""
        p = self.write("clean.go", "package main\n\nfunc main() {}\n")
        _, recs = self.run_hook(p)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["findings"], 0)
        self.assertEqual(recs[0]["analysis_status"], "partial")

    def test_line_local_engine_never_claims_clean(self):
        """partial must carry false_clean_risk: a grep cannot prove cleanliness.

        This is the cross-implementation consistency check: the hook must agree
        with shared/scripts/coverage.py, where only COMPLETE is clean.
        """
        p = self.write("clean.go", "package main\n\nfunc main() {}\n")
        _, recs = self.run_hook(p)
        self.assertTrue(recs[0]["false_clean_risk"])

    def test_unsupported_extension_is_reported(self):
        p = self.write("x.c", 'char *pw = "hunter2";\nsystem(argv[1]);\n')
        proc, recs = self.run_hook(p)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["analysis_status"], "unsupported")
        self.assertTrue(recs[0]["false_clean_risk"])
        self.assertIn("COVERAGE", proc.stderr)

    def test_truncation_is_reported_and_surfaced(self):
        body = "package main\n" + ("// filler\n" * 2200)
        p = self.write("big.go", body)
        proc, recs = self.run_hook(p)
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertTrue(r["truncated"])
        self.assertLess(r["lines_analyzed"], r["lines_total"])
        self.assertTrue(r["false_clean_risk"])
        self.assertIn("truncated", proc.stderr)

    def test_real_finding_still_reported(self):
        p = self.write("bad.go",
                       "package main\n\nfunc h(d []byte) {\n"
                       "\tsum := md5.Sum(d)\n\t_ = sum\n}\n")
        _, recs = self.run_hook(p)
        self.assertGreater(recs[0]["findings"], 0)

    def test_record_carries_the_shared_schema(self):
        p = self.write("a.go", "package main\n")
        _, recs = self.run_hook(p)
        self.assertEqual(recs[0]["schema"], "enchanter.analysis-report/v1")
        for field in ("analysis_status", "truncated", "false_clean_risk",
                      "lines_total", "lines_analyzed", "findings", "engine"):
            self.assertIn(field, recs[0])


class TestContractAgreement(unittest.TestCase):
    """The hook and the scanner must not disagree about `clean`."""

    def test_only_complete_is_clean_in_coverage_py(self):
        sys.path.insert(0, os.path.join(ROOT, "shared", "scripts"))
        import coverage as cov
        for status in (cov.PARTIAL, cov.DEGRADED, cov.UNSUPPORTED,
                       cov.UNAVAILABLE):
            r = cov.build_report("t", "f", "go", [],
                                 [cov.CoverageEntry("c", "e", cov.PATTERN,
                                                    status)])
            self.assertFalse(r["clean"], f"{status} must not be clean")
            self.assertTrue(r["false_clean_risk"])
        r = cov.build_report("t", "f", "go", [],
                             [cov.CoverageEntry("c", "e", cov.AST,
                                                cov.COMPLETE)])
        self.assertTrue(r["clean"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
