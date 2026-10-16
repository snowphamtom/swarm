#!/usr/bin/env python3
"""SWARM LEAD — direct report to Jett.

Owns the refusal-swarm run: triggers the genome batteries, collects the
judge verdict, verifies the hash-chained ledger, and files a structured
report for Jett. Reads the flow overseer's status and includes it.

Usage: python3 swarm_lead.py [--target legacy|hardened]
Reports: ~/workspace/swarm/reports/lead_report_<ts>.md + .json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SWARM = Path.home() / "workspace" / "swarm"
REFUSAL = Path.home() / "workspace" / "swarm" / "refusal_swarm.py"
REPORTS = SWARM / "reports"
FLOW_STATE = SWARM / "flow" / "flow_state.json"
LEAD_STATE = SWARM / "lead_state.json"
MARKER = SWARM / "run_in_progress.json"


def run_cli(*args):
    p = subprocess.run([sys.executable, str(REFUSAL), *args],
                       capture_output=True, text=True, timeout=900)
    return p.returncode, p.stdout, p.stderr


def main(argv=None):
    ap = argparse.ArgumentParser(prog="swarm-lead")
    ap.add_argument("--target", choices=["legacy", "hardened"], default="legacy")
    args = ap.parse_args(argv)
    REPORTS.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    MARKER.write_text(json.dumps({"ts": ts, "target": args.target}))

    run_cli("init")  # idempotent
    t0 = time.time()
    rc, out, err = run_cli("run", "--target", args.target, "--jobs", "4")
    secs = round(time.time() - t0, 1)
    try:
        run_doc = json.loads(out)
    except Exception:
        run_doc = {"parse_error": True, "stdout_tail": out[-2000:],
                   "stderr_tail": err[-2000:]}

    rc2, out2, _ = run_cli("verify-chain")
    try:
        chain = json.loads(out2)
    except Exception:
        chain = {"ok": False, "parse_error": True}

    # 3b. new-materials verification (2026-10-16 uploads: advanced codec, H14, revelations)
    nm_path = SWARM / "verify" / "verify_new_materials.py"
    newmat = {"ran": False}
    if nm_path.exists():
        p3 = subprocess.run([sys.executable, str(nm_path)],
                            capture_output=True, text=True, timeout=900)
        newmat = {"ran": True, "passed": p3.returncode == 0,
                  "tail": p3.stdout.strip().splitlines()[-1] if p3.stdout.strip() else ""}

    flow = {}
    if FLOW_STATE.exists():
        try:
            flow = json.loads(FLOW_STATE.read_text())
        except Exception:
            flow = {"status": "FLOW_STATE_UNREADABLE"}

    verdict = run_doc.get("judge", "UNKNOWN")
    report = {
        "bot": "swarm-lead", "reports_to": "Jett", "ts": ts,
        "target": args.target, "verdict": verdict,
        "genomes": run_doc.get("genomes", []),
        "adversarial_counterexamples": run_doc.get("adversarial_counterexamples"),
        "mutations_proposed": run_doc.get("mutations_proposed", []),
        "chain": chain, "run_secs": secs, "run_exit": rc,
        "new_materials": newmat,
        "flow_overseer": flow,
    }
    (REPORTS / f"lead_report_{ts}.json").write_text(json.dumps(report, indent=2))

    lines = [f"# Swarm Lead report — {ts}", "",
             f"Judge verdict: **{verdict}** (target {args.target}, {secs}s, exit {rc})",
             f"Ledger chain: {'OK' if chain.get('ok') else 'BROKEN'} "
             f"({chain.get('n', '?')} entries, tip {str(chain.get('tip'))[:16]})",
             f"New materials: {'PASSED' if newmat.get('passed') else 'FAILED / not run'}", ""]
    for g in run_doc.get("genomes", []):
        lines.append(f"- {g['id']}: {g['verdict']} (supports {g.get('supports')})")
        for r in g.get("reasons", [])[:3]:
            lines.append(f"  - {r}")
    lines += ["",
              f"Adversarial counterexamples: {run_doc.get('adversarial_counterexamples')}",
              f"Mutations proposed: {', '.join(run_doc.get('mutations_proposed', [])) or 'none'}"]
    if flow:
        lines += ["", f"Flow overseer: {flow.get('status', '?')} — {flow.get('note', '')}"]
    (REPORTS / f"lead_report_{ts}.md").write_text("\n".join(lines) + "\n")

    LEAD_STATE.write_text(json.dumps(
        {"last_ts": ts, "target": args.target, "verdict": verdict,
         "chain_ok": bool(chain.get("ok"))}, indent=2))
    if MARKER.exists():
        MARKER.unlink()
    print(json.dumps({"verdict": verdict, "chain_ok": bool(chain.get("ok")),
                      "report": f"lead_report_{ts}.md"}))


if __name__ == "__main__":
    main()
