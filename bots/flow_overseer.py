#!/usr/bin/env python3
"""FLOW OVERSEER — reports to the swarm lead; oversees the swarm's flow.

Watches: ledger tip vs entry count, hash-chain integrity, stuck run markers.
Keeps flow_state.json current for the lead to read. Never runs batteries
itself — it watches the flow; the lead runs the work.

Usage: python3 flow_overseer.py
State: ~/workspace/swarm/flow/flow_state.json
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SWARM = Path.home() / "workspace" / "swarm"
REFUSAL = Path.home() / "workspace" / "your_files" / "refusal_swarm" / "refusal_swarm.py"
FLOW = SWARM / "flow"
STATE = FLOW / "flow_state.json"
DATA = Path.home() / "refusal_swarm_data"
STUCK_AFTER_SECS = 1800


def main():
    FLOW.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    tip_p = DATA / "ledger" / "tip.json"
    entries_p = DATA / "ledger" / "entries.jsonl"
    tip = json.loads(tip_p.read_text()) if tip_p.exists() else {}
    n_entries = (sum(1 for ln in entries_p.read_text().splitlines() if ln.strip())
                 if entries_p.exists() else 0)

    p = subprocess.run([sys.executable, str(REFUSAL), "verify-chain"],
                       capture_output=True, text=True, timeout=180)
    try:
        chain = json.loads(p.stdout)
    except Exception:
        chain = {"ok": False, "parse_error": True}

    problems = []
    if tip.get("n", 0) != n_entries:
        problems.append(f"tip n={tip.get('n')} != entries on disk ({n_entries})")
    if not chain.get("ok"):
        problems.append(f"hash chain broken at entry {chain.get('break_at', '?')}")
    marker = SWARM / "run_in_progress.json"
    if marker.exists():
        age = time.time() - marker.stat().st_mtime
        if age > STUCK_AFTER_SECS:
            problems.append(f"run marker stuck for {age / 60:.0f} min")

    status = "FLOW_OK" if not problems else "FLOW_ATTENTION"
    state = {
        "bot": "flow-overseer", "reports_to": "swarm-lead", "ts": ts,
        "status": status, "tip_n": tip.get("n"), "entries": n_entries,
        "chain_ok": bool(chain.get("ok")),
        "note": "; ".join(problems) if problems
                else "ledger consistent, chain verified, no stuck runs",
    }
    STATE.write_text(json.dumps(state, indent=2) + "\n")
    (FLOW / f"flow_report_{ts}.md").write_text(
        f"# Flow overseer — {ts}\n\nStatus: **{status}**\n\n{state['note']}\n")
    print(json.dumps({"status": status, "note": state["note"]}))


if __name__ == "__main__":
    main()
