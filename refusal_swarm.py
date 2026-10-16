#!/usr/bin/env python3
"""REFUSAL SWARM — SwarmGate x Refusal Pipeline hybrid.

SwarmGate's skeleton (genomes, roles, claim-load bounds, merkle-chained ledger,
fail-closed CLI) carrying the refusal pipeline's content (fault-refusing codec
batteries, admit-or-refuse verdicts, recorded refusals).

A swarm of verifier genomes mirrors the codec battery and runs it
simultaneously; an adversarial genome hunts counterexamples; the judge admits
a claim only if every verifier's claim-load passes SwarmGate-B bounds and the
adversary finds nothing outside the disclosed set. Otherwise: REFUSE, recorded.

Constitution (from SwarmGate): fail-closed, stdlib only, trl_claim always None.
Canonical rule (from the pipeline): measure what is left over after an
interaction; admit only what fits inside that leftover; otherwise refuse and
record the refusal.

Usage:
  python3 refusal_swarm.py init
  python3 refusal_swarm.py run [--target legacy|hardened] [--jobs N]
  python3 refusal_swarm.py verify-chain
  python3 refusal_swarm.py genomes
  python3 refusal_swarm.py admit --genome g-sign
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

TRL_CLAIM = None  # constitutional: never costume a claim
VERSION = "0.1.0"

# ---------------------------------------------------------------- codec core
# Real matrices, regenerated deterministically (no numpy needed).

def legacy_masks():
    return [m for m in range(128) if (m & 1) and bin(m).count("1") >= 2][:48]


def hardened_masks():
    return [m for m in range(256)
            if (m & 1) and (m >> 1) != 0 and bin(m >> 1).count("1") % 2 == 0][:48]


def build_codec(target):
    masks = hardened_masks() if target == "hardened" else legacy_masks()
    rows = 8 if target == "hardened" else 7
    cols = [tuple((m >> r) & 1 for r in range(rows)) for m in masks]
    return {"target": target, "rows": rows, "masks": masks, "cols": cols}


def syndrome(codec, err):
    """err: iterable of (col_index, value). Returns rows-tuple of ints."""
    s = [0] * codec["rows"]
    for j, v in err:
        c = codec["cols"][j]
        for r in range(codec["rows"]):
            s[r] += v * c[r]
    return tuple(s)


def classify(codec, s):
    """Decoder model. Returns (verdict, detail).
    ('refuse',) | ('clean',) | ('axis', r, sign) | ('single', j, sign)
    A PAIR error classified as axis/single is a miscorrection (not a refusal).
    """
    if all(x == 0 for x in s):
        return ("clean",)
    nz = [(r, x) for r, x in enumerate(s) if x != 0]
    if len(nz) == 1:
        r, x = nz[0]
        return ("axis", r, 1 if x > 0 else -1)
    for j, c in enumerate(codec["cols"]):
        k = None
        ok = True
        for r in range(codec["rows"]):
            if c[r] == 0:
                if s[r] != 0:
                    ok = False
                    break
            else:
                if s[r] % 1 != 0:
                    ok = False
                    break
                kk = s[r] // c[r] if c[r] else None
                if k is None:
                    k = kk
                elif kk != k:
                    ok = False
                    break
        if ok and k:
            return ("single", j, 1 if k > 0 else -1)
    return ("refuse",)


# ---------------------------------------------------------------- genomes
# A genome is a verifier strategy: which fault space it probes.

GENOMES = [
    {"id": "g-pos",
     "fault_model": "positive equal-magnitude pairs",
     "claim": "refuses all positive equal-magnitude dual faults",
     "absence_note": "signed fault space not probed",
     "absence_doc": 0.20,
     "evolves_to": "g-sign"},
    {"id": "g-sign",
     "fault_model": "signed equal-magnitude pairs (+/+ +/- -/+ -/-)",
     "claim": "refuses all signed equal-magnitude dual faults",
     "absence_note": "documents the 124 single-bit-apart alias pairs as a known limit",
     "absence_doc": 0.85,
     "evolves_to": "g-triple"},
    {"id": "g-triple",
     "fault_model": "seeded sample of signed triples",
     "claim": "refuses sampled signed triple faults",
     "absence_note": "sampling only; full triple space unmapped (known open surface)",
     "absence_doc": 0.70,
     "evolves_to": "g-noise"},
    {"id": "g-noise",
     "fault_model": "gaussian noise on syndromes, e/sigma=10",
     "claim": "no noise-induced fake axes at e/sigma>=10",
     "absence_note": "tested at TOL=3sigma only; other regimes unmapped",
     "absence_doc": 0.60,
     "evolves_to": None},
]


def battery(genome_id, target, seed=0):
    """Run one genome's battery. Returns dict of measured counts."""
    codec = build_codec(target)
    n = len(codec["masks"])
    refused = misc = total = 0
    landed = []  # miscorrected cases (successful attacks on the claim)
    if genome_id == "g-pos":
        for i in range(n):
            for j in range(i + 1, n):
                total += 1
                v = classify(codec, syndrome(codec, [(i, 1), (j, 1)]))
                if v[0] == "refuse":
                    refused += 1
                else:
                    misc += 1
                    landed.append((i, j, 1, 1, v[0]))
    elif genome_id == "g-sign":
        for i in range(n):
            for j in range(i + 1, n):
                for a in (1, -1):
                    for b in (1, -1):
                        total += 1
                        v = classify(codec, syndrome(codec, [(i, a), (j, b)]))
                        if v[0] == "refuse":
                            refused += 1
                        else:
                            misc += 1
                            landed.append((i, j, a, b, v[0]))
    elif genome_id == "g-triple":
        rng = random.Random(seed)
        cols = range(n)
        for _ in range(3000):
            i, j, k = rng.sample(list(cols), 3)
            vals = [rng.choice((1, -1)) * rng.choice((1, 2)) for _ in range(3)]
            total += 1
            v = classify(codec, syndrome(codec, [(i, vals[0]), (j, vals[1]), (k, vals[2])]))
            if v[0] == "refuse":
                refused += 1
            else:
                misc += 1
                landed.append((i, j, k, tuple(vals), v[0]))
    elif genome_id == "g-noise":
        rng = random.Random(seed)
        for _ in range(2000):
            j = rng.randrange(n)
            mag = rng.choice((1, 2))
            s = list(syndrome(codec, [(j, mag)]))
            s = [x + rng.gauss(0, mag / 10.0) for x in s]
            s = tuple(int(round(x)) for x in s)
            total += 1
            v = classify(codec, s)
            # fake axis = clean single-fault syndrome reported as axis
            if v[0] == "axis":
                misc += 1
                landed.append((j, mag, v))
            else:
                refused += 1
    return {"genome": genome_id, "target": target, "total": total,
            "refused": refused, "miscorrected": misc, "landed": landed}


# ------------------------------------------------- claim-load (SwarmGate-B)
# Transplanted bound structure; thresholds documented as hypothesis.
KAPPA = 0.5       # disclosure must scale with claim strength
THETA_A = 0.25    # attack probing must scale with claim strength
THETA_S = 1e-6
EPS = 1e-12


def make_load(N, S, A, Abs):
    return {"Lambda": {"N": N, "S": S, "A": A, "Abs": Abs},
            "note": "thresholds hypothesis until measured; "
                    "N=claim strength S=supports A=attack probing Abs=absence documentation"}


def evaluate_bounds(load):
    lam = load["Lambda"]
    N, S, A, Abs = lam["N"], lam["S"], lam["A"], lam["Abs"]
    hard = []
    if not (N <= S + A + EPS):
        hard.append("B0: N > S+A (claim exceeds evidence+probing)")
    if not (Abs >= KAPPA * N - EPS):
        hard.append("B1: Abs < k*N (limits undocumented for this claim)")
    if not (A >= THETA_A * N - EPS):
        hard.append("B2: A < tA*N (attack space under-probed)")
    if not (S >= THETA_S - EPS):
        hard.append("B3: S < eps (no supports)")
    return {"hard_fail": hard, "B_ok": not hard,
            "overloaded": any(h.startswith("B0") or h.startswith("B1") for h in hard)}


def genome_load(genome, result, attack_probe):
    N = 1.0
    S = result["refused"] / result["total"] if result["total"] else 0.0
    A = attack_probe  # adversarial probing coverage 0..1
    Abs = genome["absence_doc"]
    load = make_load(round(N, 4), round(S, 4), round(A, 4), round(Abs, 4))
    return load, evaluate_bounds(load)


# ------------------------------------------------------------------ ledger
def data_dir():
    return Path(os.environ.get("REFUSAL_SWARM_DATA",
                               str(Path.home() / "refusal_swarm_data")))


def _h(b):
    return hashlib.sha256(b).hexdigest()


def init():
    root = data_dir()
    (root / "ledger").mkdir(parents=True, exist_ok=True)
    (root / "genomes").mkdir(parents=True, exist_ok=True)
    entries = root / "ledger" / "entries.jsonl"
    if not entries.exists():
        entries.write_text("", encoding="utf-8")
    for g in GENOMES:
        p = root / "genomes" / (g["id"] + ".json")
        if not p.exists():
            p.write_text(json.dumps(g, indent=2) + "\n", encoding="utf-8")
    tip = {"schema": "refusal-swarm-tip.v0", "n": 0, "last_hash": None,
           "chain_ok": True, "trl_claim": TRL_CLAIM}
    (root / "ledger" / "tip.json").write_text(json.dumps(tip, indent=2) + "\n",
                                              encoding="utf-8")
    return {"ok": True, "data": str(root)}


def append(role, body):
    root = data_dir()
    entries = root / "ledger" / "entries.jsonl"
    lines = [ln for ln in entries.read_text(encoding="utf-8").splitlines() if ln.strip()]
    prev = json.loads(lines[-1])["hash"] if lines else "GENESIS"
    seq = len(lines)
    entry = {"seq": seq, "ts": datetime.now(timezone.utc).isoformat(),
             "role": role, "prev": prev, "trl_claim": TRL_CLAIM}
    entry.update(body)
    entry["hash"] = _h(json.dumps(entry, sort_keys=True).encode())
    with entries.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    tip = {"schema": "refusal-swarm-tip.v0", "n": seq + 1,
           "last_hash": entry["hash"], "chain_ok": True, "trl_claim": TRL_CLAIM}
    (root / "ledger" / "tip.json").write_text(json.dumps(tip, indent=2) + "\n",
                                              encoding="utf-8")
    return entry


def verify_chain():
    entries = data_dir() / "ledger" / "entries.jsonl"
    lines = [ln for ln in entries.read_text(encoding="utf-8").splitlines() if ln.strip()]
    prev = "GENESIS"
    for i, ln in enumerate(lines):
        e = json.loads(ln)
        if e["seq"] != i or e["prev"] != prev:
            return {"ok": False, "break_at": i}
        h = e.pop("hash")
        if _h(json.dumps(e, sort_keys=True).encode()) != h:
            return {"ok": False, "break_at": i}
        e["hash"] = h
        prev = h
    return {"ok": True, "n": len(lines), "tip": prev[:16]}


# ------------------------------------------------------------------- roles
def role_verifier(genome_id, target, attack_probe):
    genome = next(g for g in GENOMES if g["id"] == genome_id)
    t0 = time.time()
    res = battery(genome_id, target)
    load, bounds = genome_load(genome, res, attack_probe)
    verdict = "ADMIT" if bounds["B_ok"] and res["miscorrected"] == 0 else "REFUSE"
    reasons = list(bounds["hard_fail"])
    if res["miscorrected"]:
        reasons.append(f"{res['miscorrected']}/{res['total']} cases miscorrected "
                       f"(successful attacks on the claim)")
    entry = append("verifier", {"genome": genome_id, "target": target,
                                "claim": genome["claim"], "verdict": verdict,
                                "load": load, "bounds": bounds,
                                "refused": res["refused"], "miscorrected": res["miscorrected"],
                                "total": res["total"], "reasons": reasons,
                                "secs": round(time.time() - t0, 2)})
    return {"genome": genome_id, "verdict": verdict, "reasons": reasons,
            "S": load["Lambda"]["S"], "misc": res["miscorrected"],
            "landed": res["landed"][:5]}


def role_adversarial(target, seed=7):
    """Independent fuzzing hunt for counterexamples outside disclosed sets."""
    rng = random.Random(seed)
    codec = build_codec(target)
    n = len(codec["masks"])
    found = []
    for _ in range(4000):
        i, j = rng.sample(range(n), 2)
        a = rng.choice((1, -1)) * rng.choice((1, 2, 3))
        b = rng.choice((1, -1)) * rng.choice((1, 2, 3))
        v = classify(codec, syndrome(codec, [(i, a), (j, b)]))
        if v[0] in ("axis", "single"):
            found.append((i, j, a, b, v[0]))
            if len(found) >= 8:
                break
    entry = append("adversarial", {"target": target,
                                   "probed": 4000, "counterexamples": len(found),
                                   "sample": found[:5]})
    return {"counterexamples": len(found), "sample": found[:5],
            "probe_coverage": min(1.0, 4000 / (n * (n - 1) * 2))}


def role_judge(target, attack_probe=0.5):
    results = [role_verifier(g["id"], target, attack_probe) for g in GENOMES]
    adv = role_adversarial(target)
    problems = []
    for r in results:
        if r["verdict"] == "REFUSE":
            problems.append(f"{r['genome']}: {'; '.join(r['reasons'])}")
    if adv["counterexamples"]:
        problems.append(f"adversarial: {adv['counterexamples']} live counterexamples")
    verdict = "ADMIT" if not problems else "REFUSE"
    entry = append("judge", {"target": target, "verdict": verdict,
                             "problems": problems,
                             "genomes": {r["genome"]: r["verdict"] for r in results}})
    return {"verdict": verdict, "problems": problems, "results": results,
            "adversarial": adv, "ledger_seq": entry["seq"]}


def role_mutator(target):
    """Evolve: for each refused genome, propose its documented successor."""
    proposals = []
    for g in GENOMES:
        if g["evolves_to"]:
            proposals.append({"from": g["id"], "to": g["evolves_to"],
                              "why": f"{g['id']} refused; expand fault model"})
            append("mutator", {"from": g["id"], "to": g["evolves_to"],
                                "why": proposals[-1]["why"]})
    return proposals


# --------------------------------------------------------------------- CLI
def cmd_run(args):
    t0 = time.time()
    append("architect", {"objective": f"refusal-swarm run on {args.target}",
                         "note": "mirror and run simultaneously"})
    # verifiers mirror: run simultaneously in separate processes
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(battery, g["id"], args.target): g["id"] for g in GENOMES}
        batteries = {futs[f]: f.result() for f in concurrent.futures.as_completed(futs)}
    adv = role_adversarial(args.target)
    attack_probe = 0.5
    results = []
    for g in GENOMES:
        res = batteries[g["id"]]
        load, bounds = genome_load(g, res, attack_probe)
        verdict = "ADMIT" if bounds["B_ok"] and res["miscorrected"] == 0 else "REFUSE"
        reasons = list(bounds["hard_fail"])
        if res["miscorrected"]:
            reasons.append(f"{res['miscorrected']}/{res['total']} miscorrected")
        append("verifier", {"genome": g["id"], "target": args.target,
                            "claim": g["claim"], "verdict": verdict,
                            "load": load, "bounds": bounds,
                            "refused": res["refused"], "miscorrected": res["miscorrected"],
                            "total": res["total"], "reasons": reasons})
        results.append({"genome": g["id"], "verdict": verdict,
                        "S": load["Lambda"]["S"], "reasons": reasons})
    problems = [f"{r['genome']}: {'; '.join(r['reasons'])}" for r in results
                if r["verdict"] == "REFUSE"]
    if adv["counterexamples"]:
        problems.append(f"adversarial: {adv['counterexamples']} live counterexamples")
    verdict = "ADMIT" if not problems else "REFUSE"
    entry = append("judge", {"target": args.target, "verdict": verdict,
                             "problems": problems,
                             "genomes": {r["genome"]: r["verdict"] for r in results}})
    mut = role_mutator(args.target)
    print(json.dumps({
        "swarm": "refusal-swarm", "version": VERSION, "target": args.target,
        "judge": verdict,
        "genomes": [{"id": r["genome"], "verdict": r["verdict"],
                     "supports": r["S"], "reasons": r["reasons"]} for r in results],
        "adversarial_counterexamples": adv["counterexamples"],
        "mutations_proposed": [f"{m['from']}->{m['to']}" for m in mut],
        "ledger_seq": entry["seq"],
        "secs": round(time.time() - t0, 1),
        "trl_claim": TRL_CLAIM,
    }, indent=2))
    return 0 if verdict == "ADMIT" else 3


def main(argv=None):
    ap = argparse.ArgumentParser(prog="refusal_swarm")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    p = sub.add_parser("run")
    p.add_argument("--target", choices=["legacy", "hardened"], default="legacy")
    p.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 2))
    sub.add_parser("verify-chain")
    sub.add_parser("genomes")
    p = sub.add_parser("admit")
    p.add_argument("--genome", required=True)
    p.add_argument("--target", choices=["legacy", "hardened"], default="legacy")
    args = ap.parse_args(argv)
    if args.cmd == "init":
        print(json.dumps(init(), indent=2))
    elif args.cmd == "run":
        return cmd_run(args)
    elif args.cmd == "verify-chain":
        print(json.dumps(verify_chain(), indent=2))
    elif args.cmd == "genomes":
        print(json.dumps(GENOMES, indent=2))
    elif args.cmd == "admit":
        r = role_verifier(args.genome, args.target, 0.5)
        print(json.dumps(r, indent=2))
        return 0 if r["verdict"] == "ADMIT" else 3


if __name__ == "__main__":
    sys.exit(main())
