#!/usr/bin/env python3
"""
R8: EMA Posture Decay
Cross-session security posture tracking with EMA (alpha=0.3).
Tracks recurring vulnerability types, dismissed patterns, and threat rates.

Usage:
    python3 learnings.py <state_dir> [--update] [--report]
"""

import json
import os
import sys
from collections import Counter
from datetime import datetime


EMA_ALPHA = 0.3  # Exponential moving average learning rate


def load_learnings(learnings_path):
    """Load existing learnings from JSON file."""
    if os.path.exists(learnings_path):
        try:
            with open(learnings_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    return {
        "version": "1.0.0",
        "sessions": 0,
        "threat_rates": {},
        "dismissed_patterns": {},
        "chronic_patterns": [],
        "posture_history": [],
        "last_updated": None,
    }


def save_learnings(learnings, learnings_path):
    """Save learnings to JSON file atomically."""
    tmp_path = learnings_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(learnings, f, indent=2)
    os.replace(tmp_path, learnings_path)


def load_audit_events(audit_path):
    """Load events from audit.jsonl."""
    events = []
    if not os.path.exists(audit_path):
        return events

    try:
        with open(audit_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except (OSError, IOError):
        pass

    return events


def compute_session_rates(events):
    """Compute threat rates for the current session."""
    rates = Counter()

    for event in events:
        event_type = event.get("event", "")
        if event_type == "secret_detected":
            pattern_id = event.get("pattern_id", "unknown")
            rates[f"secret:{pattern_id}"] += 1
        elif event_type == "vuln_detected":
            cwe = event.get("cwe", "unknown")
            rates[f"vuln:{cwe}"] += 1
        elif event_type == "action_blocked":
            reason = event.get("reason", event.get("op_id", "unknown"))
            rates[f"block:{reason}"] += 1
        elif event_type == "config_attack_detected":
            attack_id = event.get("attack_id", "unknown")
            rates[f"config:{attack_id}"] += 1

    return dict(rates)


def update_ema(old_rate, new_count, alpha=EMA_ALPHA):
    """
    Update rate using Exponential Moving Average.
    r_new = alpha * s_current + (1 - alpha) * r_prior
    """
    return alpha * new_count + (1.0 - alpha) * old_rate


def compute_posture(initial_threats, current_threats):
    """
    Compute security posture score.
    Posture(t) = 1 - (Theta_t / Theta_0)
    """
    if initial_threats <= 0:
        return 1.0
    return max(0.0, min(1.0, 1.0 - (current_threats / initial_threats)))


def update_learnings(state_dir):
    """Update learnings with current session data."""
    learnings_path = os.path.join(state_dir, "learnings.json")
    audit_path = os.path.join(state_dir, "audit.jsonl")

    learnings = load_learnings(learnings_path)
    events = load_audit_events(audit_path)

    if not events:
        return learnings

    session_rates = compute_session_rates(events)
    learnings["sessions"] += 1

    # Update EMA threat rates
    for key, count in session_rates.items():
        old_rate = learnings["threat_rates"].get(key, 0.0)
        learnings["threat_rates"][key] = round(update_ema(old_rate, count), 4)

    # Decay rates for patterns NOT seen this session
    for key in list(learnings["threat_rates"].keys()):
        if key not in session_rates:
            learnings["threat_rates"][key] = round(
                update_ema(learnings["threat_rates"][key], 0), 4
            )
            # Remove negligible rates
            if learnings["threat_rates"][key] < 0.01:
                del learnings["threat_rates"][key]

    # Detect chronic patterns (appeared in >3 sessions with rate > 0.5)
    learnings["chronic_patterns"] = [
        key for key, rate in learnings["threat_rates"].items()
        if rate > 0.5 and learnings["sessions"] >= 3
    ]

    # Compute posture
    total_threats = sum(session_rates.values())
    initial = max(total_threats, learnings.get("initial_threats", total_threats))
    if "initial_threats" not in learnings:
        learnings["initial_threats"] = total_threats

    posture = compute_posture(initial, total_threats)
    learnings["posture_history"].append({
        "session": learnings["sessions"],
        "posture": round(posture, 4),
        "threats": total_threats,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })

    # Keep only last 50 posture entries
    learnings["posture_history"] = learnings["posture_history"][-50:]
    learnings["last_updated"] = datetime.utcnow().isoformat() + "Z"

    save_learnings(learnings, learnings_path)
    return learnings


def generate_report(state_dir):
    """Generate a learnings summary report."""
    learnings_path = os.path.join(state_dir, "learnings.json")
    learnings = load_learnings(learnings_path)

    report = {
        "sessions_analyzed": learnings["sessions"],
        "top_threats": sorted(
            learnings["threat_rates"].items(),
            key=lambda x: -x[1]
        )[:10],
        "chronic_patterns": learnings["chronic_patterns"],
        "dismissed_count": len(learnings["dismissed_patterns"]),
        "current_posture": (
            learnings["posture_history"][-1]["posture"]
            if learnings["posture_history"] else None
        ),
        "last_updated": learnings["last_updated"],
    }

    return report


def main():
    if len(sys.argv) < 2:
        print("Usage: learnings.py <state_dir> [--update] [--report]", file=sys.stderr)
        sys.exit(1)

    state_dir = sys.argv[1]
    action = sys.argv[2] if len(sys.argv) > 2 else "--report"

    if action == "--update":
        learnings = update_learnings(state_dir)
        print(json.dumps({"updated": True, "sessions": learnings["sessions"]}))
    elif action == "--report":
        report = generate_report(state_dir)
        print(json.dumps(report, indent=2))
    else:
        print(f"Unknown action: {action}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
