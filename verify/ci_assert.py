#!/usr/bin/env python3
"""CI assertions for the swarm repo.

Pins the exact measured behavior of every swarm component. Any deviation
— code change, data change, environment change — fails the build loudly
instead of drifting silently.

Expected signatures (measured 2026-10-16, deterministic seeds):
  legacy:   judge REFUSE; misc {g-pos:0, g-sign:248, g-triple:69, g-noise:0}; adversarial 8
  hardened: judge REFUSE; misc {g-pos:0, g-sign:0,  g-triple:48, g-noise:0}; adversarial 0
  new materials: verify_new_materials.py exits 0 (27 checks)
  ledger: hash chain verifies after the run.

Exit 0 iff everything matches.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import refusal_swarm as rs  # noqa: E402

FAILS: list[str] = []


def check(name, cond, detail=""):
    print(f"  [{'OK' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        FAILS.append(name)


EXPECTED = {
    "legacy": {"judge": "REFUSE",
               "misc": {"g-pos": 0, "g-sign": 248, "g-triple": 69, "g-noise": 0},
               "adversarial": 8},
    "hardened": {"judge": "REFUSE",
                 "misc": {"g-pos": 0, "g-sign": 0, "g-triple": 48, "g-noise": 0},
                 "adversarial": 0},
}


def main():
    rs.init()
    for target, exp in EXPECTED.items():
        print(f"target={target}")
        out = rs.role_judge(target)
        check(f"{target} judge == {exp['judge']}", out["verdict"] == exp["judge"],
              f"got {out['verdict']}")
        for r in out["results"]:
            want = exp["misc"][r["genome"]]
            check(f"{target}/{r['genome']} misc == {want}", r["misc"] == want,
                  f"got {r['misc']}")
        check(f"{target} adversarial == {exp['adversarial']}",
              out["adversarial"]["counterexamples"] == exp["adversarial"],
              f"got {out['adversarial']['counterexamples']}")

    print("new materials")
    p = subprocess.run([sys.executable, str(REPO / "verify" / "verify_new_materials.py")],
                       capture_output=True, text=True, timeout=900)
    check("verify_new_materials.py exits 0", p.returncode == 0,
          p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr[-500:])

    print("ledger")
    chain = rs.verify_chain()
    check("hash chain verifies", chain.get("ok") is True, str(chain))

    print()
    if FAILS:
        print(f"CI FAILED: {FAILS}")
        return 1
    print("CI: ALL SWARM ASSERTIONS PINNED AND PASSING")
    return 0


if __name__ == "__main__":
    sys.exit(main())
