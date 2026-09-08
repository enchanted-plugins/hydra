#!/usr/bin/env python3
"""Analysis-coverage contract (enchanter.analysis-report/v1).

The law this module exists to enforce:

    ZERO FINDINGS + INCOMPLETE COVERAGE MUST NEVER MEAN CLEAN.

A scanner that returns `[]` is making one of several very different
statements, and callers cannot currently tell them apart:

  * "I analysed this fully and found nothing."          -> complete
  * "I analysed the first 2000 lines and found nothing." -> partial (truncated)
  * "I only match single lines, so cross-line taint is
     invisible to me."                                   -> partial (by depth)
  * "I have no rules for this language at all."          -> unsupported
  * "My backing analyzer is missing/timed out."          -> degraded/unavailable

Only the first one is `clean`. This module makes the distinction explicit
and machine-readable so a downstream tool (or an LLM reviewer) can refuse
to treat an empty finding list as assurance.
"""

from __future__ import annotations

SCHEMA = "enchanter.analysis-report/v1"

# Analysis status, ordered from strongest to weakest claim.
COMPLETE = "complete"        # the class was fully analysed at the stated depth
PARTIAL = "partial"          # analysed, but with known blind spots
DEGRADED = "degraded"        # the engine ran but lost fidelity (timeout, truncation)
UNSUPPORTED = "unsupported"  # no capability for this class/language
UNAVAILABLE = "unavailable"  # the engine could not run at all

_RANK = {
    COMPLETE: 0,
    PARTIAL: 1,
    DEGRADED: 2,
    UNSUPPORTED: 3,
    UNAVAILABLE: 4,
}

# Analysis depth, ordered from weakest to strongest.
PATTERN = "pattern"                    # regex / token matching
AST = "ast"                            # syntax-tree aware
INTRAPROCEDURAL = "intraprocedural"    # dataflow within a function
INTERPROCEDURAL = "interprocedural"    # dataflow across functions


class CoverageEntry:
    """One (defect class, engine) coverage claim."""

    def __init__(
        self,
        cls,
        engine,
        depth,
        status,
        shapes_supported=None,
        shapes_unsupported=None,
        truncated=False,
        notes="",
    ):
        self.cls = cls
        self.engine = engine
        self.depth = depth
        self.status = status
        self.shapes_supported = list(shapes_supported or [])
        self.shapes_unsupported = list(shapes_unsupported or [])
        self.truncated = bool(truncated)
        self.notes = notes

    def to_dict(self):
        return {
            "class": self.cls,
            "engine": self.engine,
            "depth": self.depth,
            "status": self.status,
            "shapes_supported": self.shapes_supported,
            "shapes_unsupported": self.shapes_unsupported,
            "truncated": self.truncated,
            "notes": self.notes,
        }


def worst_status(entries):
    """Return the weakest claim across all coverage entries.

    An overall report is only as trustworthy as its least-covered class.
    """
    if not entries:
        return UNAVAILABLE
    return max((e.status for e in entries), key=lambda s: _RANK.get(s, 9))


def build_report(tool, target_path, language, findings, coverage,
                 lines_total=None, lines_analyzed=None, tool_version=None):
    """Assemble the full analysis report.

    `false_clean_risk` is the field callers should branch on: it is True
    whenever an empty (or partial) finding list is NOT evidence of safety.
    """
    overall = worst_status(coverage)
    truncated = any(e.truncated for e in coverage)

    # The core law. Zero findings only means "clean" when every class was
    # analysed completely and nothing was truncated.
    false_clean_risk = (overall != COMPLETE) or truncated

    return {
        "schema": SCHEMA,
        "tool": tool,
        "tool_version": tool_version,
        "target": {
            "path": target_path,
            "language": language,
            "lines_total": lines_total,
            "lines_analyzed": lines_analyzed,
        },
        "analysis_status": overall,
        "truncated": truncated,
        "false_clean_risk": false_clean_risk,
        "clean": (len(findings) == 0 and not false_clean_risk),
        "coverage": [e.to_dict() for e in coverage],
        "findings": findings,
    }


def human_summary(report):
    """One-line operator summary that never implies unearned assurance."""
    n = len(report.get("findings") or [])
    status = report.get("analysis_status")
    if n == 0 and report.get("false_clean_risk"):
        return (
            f"NO FINDINGS, BUT COVERAGE IS {status.upper()} — this is NOT a "
            f"clean result. Uncovered: "
            + ", ".join(
                e["class"] for e in report.get("coverage", [])
                if e["status"] != COMPLETE
            )
        )
    if n == 0:
        return "clean: all declared classes analysed completely, no findings"
    return f"{n} finding(s); coverage status {status}"
