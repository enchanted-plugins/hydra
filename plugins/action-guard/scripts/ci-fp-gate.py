#!/usr/bin/env python3
"""
ci-fp-gate: CI gate that promotes action-guard from an advisory-only runtime
hook to a CI-blocking correctness check on its enforcement classification.

Closes VF-05 (fail-closed rebuild). Verifies two properties by driving the
real guard-action.sh hook with HYDRA_ENFORCE=enforce:

  1. FALSE-POSITIVE safety: every command in fixtures/fp-corpus.json — normal,
     legitimate developer commands — must NOT be denied. (permissionDecision
     may be absent, "ask", or a warn advisory — never "deny".)

  2. TRUE-POSITIVE coverage: every case in fixtures/tp-corpus.json — the
     catastrophic/irreversible deny tier — MUST produce permissionDecision
     "deny".

Any FP-block or TP-miss fails the gate (non-zero exit), which fails CI.

Runtime hook semantics are unchanged for the default rollout: guard-action.sh
ships in SHADOW mode (HYDRA_ENFORCE unset) and blocks nothing until a human
flips HYDRA_ENFORCE=enforce. This gate exercises the enforce path directly so
the classification is verified without changing the default posture.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = PLUGIN_ROOT / "fixtures"
FP_FILE = FIXTURE_DIR / "fp-corpus.json"
TP_FILE = FIXTURE_DIR / "tp-corpus.json"
HOOK = PLUGIN_ROOT / "hooks" / "pre-tool-use" / "guard-action.sh"
DEFAULT_BASELINE = PLUGIN_ROOT / "baseline-2026-08-19.json"

# 60 chained subcommands — exceeds HYDRA_SUBCOMMAND_LIMIT (50). Placeholder in
# the TP corpus keeps the committed fixture readable.
OVERFLOW_CMD = "".join(f"echo {i}; " for i in range(1, 61))


def _load_json(path: Path) -> dict:
    if not path.exists():
        sys.stderr.write(f"FAIL: fixture missing: {path}\n")
        sys.exit(2)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"FAIL: cannot parse {path.name}: {e}\n")
        sys.exit(2)


def _bash() -> str:
    """Resolve a bash that understands the hook's paths.

    Linux CI: plain `bash`. Windows: Git Bash (WSL's bash mangles C:/ paths).
    Honor HYDRA_BASH to override.
    """
    import os
    import shutil

    override = os.environ.get("HYDRA_BASH")
    if override:
        return override
    if os.name == "nt":
        for cand in (
            r"C:\Program Files\Git\usr\bin\bash.exe",
            r"C:\Program Files\Git\bin\bash.exe",
        ):
            if Path(cand).exists():
                return cand
    return shutil.which("bash") or "bash"


def _run_hook(command: str) -> tuple[int, str]:
    """Run guard-action.sh in enforce mode; return (rc, stdout)."""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    try:
        result = subprocess.run(
            [_bash(), HOOK.as_posix()],
            input=payload,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            env={**_base_env(), "HYDRA_ENFORCE": "enforce"},
        )
    except Exception as e:  # noqa: BLE001
        return 99, f"__RUN_ERROR__ {e}"
    return result.returncode, result.stdout or ""


def _base_env() -> dict:
    import os

    env = dict(os.environ)
    # bash (Git Bash on Windows) mangles backslash paths — hand it a posix path.
    env["CLAUDE_PLUGIN_ROOT"] = PLUGIN_ROOT.as_posix()
    return env


def _permission_decision(stdout: str) -> str | None:
    """Extract hookSpecificOutput.permissionDecision from hook stdout, if any."""
    stdout = stdout.strip()
    if not stdout:
        return None
    # The hook emits exactly one JSON object on stdout when it decides.
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        hso = obj.get("hookSpecificOutput", {})
        if hso.get("hookEventName") == "PreToolUse":
            return hso.get("permissionDecision")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(prog="ci-fp-gate")
    parser.add_argument(
        "--baseline",
        nargs="?",
        const=str(DEFAULT_BASELINE),
        default=None,
        help=(
            "Compare against a recorded baseline JSON; fail if FP-safety or "
            "TP-coverage regresses. Pass the flag alone to use the default "
            f"baseline at {DEFAULT_BASELINE.name}."
        ),
    )
    parser.add_argument(
        "--write-baseline",
        metavar="PATH",
        default=None,
        help="Write a fresh baseline JSON to PATH and exit 0 (recording mode).",
    )
    args = parser.parse_args()

    if not HOOK.exists():
        sys.stderr.write(f"FAIL: hook missing: {HOOK}\n")
        return 2

    fp = _load_json(FP_FILE).get("commands", [])
    tp = _load_json(TP_FILE).get("cases", [])
    if len(fp) < 90:
        sys.stderr.write(f"FAIL: expected >= 90 FP commands, found {len(fp)}\n")
        return 2
    if len(tp) < 20:
        sys.stderr.write(f"FAIL: expected >= 20 TP cases, found {len(tp)}\n")
        return 2

    fp_blocks: list[str] = []  # FPs that were wrongly denied
    tp_misses: list[str] = []  # TPs that were NOT denied

    # ── FALSE-POSITIVE pass ──
    for cmd in fp:
        rc, out = _run_hook(cmd)
        decision = _permission_decision(out)
        if decision == "deny":
            fp_blocks.append(cmd)

    # ── TRUE-POSITIVE pass ──
    tp_pass: list[str] = []
    for case in tp:
        cid = case.get("id", "?")
        cmd = case.get("command", "")
        if cmd == "__OVERFLOW__":
            cmd = OVERFLOW_CMD
        rc, out = _run_hook(cmd)
        decision = _permission_decision(out)
        if decision == "deny":
            tp_pass.append(cid)
        else:
            tp_misses.append(f"{cid}: decision={decision!r}")

    fp_total, tp_total = len(fp), len(tp)
    fp_ok = fp_total - len(fp_blocks)

    result = {
        "recorded": "2026-08-19",
        "fp_total": fp_total,
        "fp_denied": len(fp_blocks),
        "fp_pass_rate": round(fp_ok / fp_total, 4) if fp_total else 0.0,
        "tp_total": tp_total,
        "tp_denied": len(tp_pass),
        "tp_coverage": round(len(tp_pass) / tp_total, 4) if tp_total else 0.0,
    }

    if args.write_baseline:
        Path(args.write_baseline).write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        sys.stdout.write(f"baseline written to {args.write_baseline}\n")
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
        return 0

    # ── Report ──
    sys.stdout.write("=== action-guard FP/TP CI gate (enforce mode) ===\n")
    sys.stdout.write(f"FP corpus: {fp_total} commands, {len(fp_blocks)} wrongly denied\n")
    sys.stdout.write(f"TP corpus: {tp_total} cases, {len(tp_pass)} correctly denied\n")
    for c in fp_blocks:
        sys.stdout.write(f"  FP-BLOCK (must not deny): {c}\n")
    for m in tp_misses:
        sys.stdout.write(f"  TP-MISS  (must deny): {m}\n")

    if args.baseline:
        base = _load_json(Path(args.baseline))
        msgs = []
        if result["fp_pass_rate"] < base.get("fp_pass_rate", 1.0):
            msgs.append(
                f"FP pass-rate regressed: {result['fp_pass_rate']} < "
                f"{base.get('fp_pass_rate')}"
            )
        if result["tp_coverage"] < base.get("tp_coverage", 1.0):
            msgs.append(
                f"TP coverage regressed: {result['tp_coverage']} < "
                f"{base.get('tp_coverage')}"
            )
        for m in msgs:
            sys.stdout.write(f"  REGRESSION: {m}\n")
        if msgs:
            sys.stdout.write("\nVF-05 CI gate FAILED: regression vs baseline.\n")
            return 1

    if fp_blocks or tp_misses:
        sys.stdout.write(
            "\nVF-05 CI gate FAILED: "
            f"{len(fp_blocks)} false-positive block(s), "
            f"{len(tp_misses)} true-positive miss(es).\n"
        )
        return 1

    sys.stdout.write(
        "\nVF-05 CI gate PASSED: 0 false-positive blocks, "
        f"all {tp_total} deny-tier commands denied.\n"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
