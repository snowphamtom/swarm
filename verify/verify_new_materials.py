#!/usr/bin/env python3
"""Swarm verification of the 2026-10-16 new materials (independent recompute).

Targets:
  A. codec_advanced.py improved C(7,48) — sandwich 5452, XOR triples 12780,
     101 single-row pairs, 4512 pair events refused / 0 miscorrected.
  B. full_matrix.txt H14 (evolved 96-alias set) — row sums, 96 aliases,
     96/96 kills at exactly popcount 2, 0 new popcount-1 pairs,
     bit uniformity 16 per bit, weight distribution 6/7/18/12/4/1.
  C. revelations evolved mask set — 96 aliases by M_i ^ M_j = 2^k.

All numbers recomputed here from the files, not copied from the documents.
Exit 0 iff every check passes.
"""
from __future__ import annotations

import json
import re
import sys
from itertools import combinations
from pathlib import Path

USER_FILES = Path.home() / "workspace" / "user" / "files"
FAILS: list[str] = []


def check(name, cond, detail=""):
    print(f"  [{'OK' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        FAILS.append(name)


def popcount(x: int) -> int:
    return bin(x).count("1")


# ---------------------------------------------------------------- A. codec_advanced
print("A. codec_advanced.py improved instance")
sys.path.insert(0, str(USER_FILES))
import codec_advanced as ca  # noqa: E402

check("48 masks", len(ca.IMPROVED_MASKS) == 48)
check("all odd, weight>=2",
      all((m & 1) and popcount(m) >= 2 for m in ca.IMPROVED_MASKS))
check("XOR triples == 12780", ca._N_XOR == 12780, f"got {ca._N_XOR}")
check("sandwich triples == 5452", ca._N_SAND == 5452, f"got {ca._N_SAND}")
check("reduction == 23.6%",
      abs((7140 - ca._N_SAND) / 7140 * 100 - 23.6) < 0.05,
      f"got {(7140 - ca._N_SAND) / 7140 * 100:.2f}%")
check("single-row pairs == 101", ca.N_SINGLE_ROW_PAIRS == 101,
      f"got {ca.N_SINGLE_ROW_PAIRS}")

ok, total = ca.battery_singles()
check("singles+parity 55/55", ok == total == 55, f"got {ok}/{total}")
r, mc, mcl = ca.battery_pairs()
check("pairs 4512 refused", r == 4512, f"got {r}")
check("pairs 0 miscorrected", mc == 0, f"got {mc}")
check("pairs 0 misclassified", mcl == 0, f"got {mcl}")
r3, mc3, n3 = ca.battery_triple_sample(2000, seed=42)
check("triple sample 2000 refused", r3 == 2000, f"got {r3}")
check("triple sample 0 miscorrected", mc3 == 0, f"got {mc3}")

# ---------------------------------------------------------------- B. H14 full matrix
print("B. full_matrix.txt H14 (evolved set)")
txt = (USER_FILES / "full_matrix.txt").read_text()
rows = re.findall(r"^row\s+\d+.*?:\s*([01]{48})", txt, re.M)
check("14 rows parsed", len(rows) == 14, f"got {len(rows)}")
H14 = [[int(ch) for ch in row] for row in rows]  # H14[r][j]
sums = [sum(H14[r][j] for j in range(48)) for r in range(14)]
check("row sums", sums == [48, 25, 24, 24, 24, 25, 26, 48, 23, 24, 24, 24, 23, 22],
      f"got {sums}")
check("total ones == 384", sum(sums) == 384, f"got {sum(sums)}")

masks = [int(x) for x in re.search(r"Masks \(columns 0-47\):\s*([0-9, ]+)",
                                  txt).group(1).split(",")]
check("48 evolved masks", len(masks) == 48)
upper = [sum(H14[r][j] << r for r in range(7)) for j in range(48)]
check("upper half == evolved masks", upper == masks)
ext = [int(x) for x in re.search(r"Extended masks \(rows 7-13\):\s*([0-9, ]+)",
                                 txt).group(1).split(",")]
lower = [sum(H14[7 + r][j] << r for r in range(7)) for j in range(48)]
check("lower half == extended masks", lower == ext)

# alias pairs on the evolved set: M_i ^ M_j == 2^k
aliases = []
for i, j in combinations(range(48), 2):
    d = masks[i] ^ masks[j]
    if d and (d & (d - 1)) == 0:
        aliases.append((i, j, d.bit_length() - 1))
check("alias pairs == 96", len(aliases) == 96, f"got {len(aliases)}")

# bit uniformity: 16 aliases per bit position (bits 1..6)
per_bit = [sum(1 for _, _, k in aliases if k == b) for b in range(1, 7)]
check("bit uniformity 16x6", per_bit == [16] * 6, f"got {per_bit}")

# weight distribution of evolved masks
wd = [sum(1 for m in masks if popcount(m) == w) for w in range(2, 8)]
check("weights 6/7/18/12/4/1", wd == [6, 7, 18, 12, 4, 1], f"got {wd}")

# H14 kill check: opposite-sign pair syndrome popcount == 2 for all 96 aliases
def syndrome14(i, a, j, b):
    return [a * H14[r][i] + b * H14[r][j] for r in range(14)]

kills = sum(1 for i, j, _ in aliases
            if sum(1 for x in syndrome14(i, 1, j, -1) if x != 0) == 2)
check("96/96 alias kills at pc=2", kills == 96, f"got {kills}")

# no NEW popcount-1 pairs on the full 14-row matrix (all sign combos)
new_pc1 = 0
for i, j in combinations(range(48), 2):
    for a, b in ((1, 1), (1, -1), (-1, 1), (-1, -1)):
        if sum(1 for x in syndrome14(i, a, j, b) if x != 0) == 1:
            new_pc1 += 1
            break
check("0 new popcount-1 pairs", new_pc1 == 0, f"got {new_pc1}")

# ---------------------------------------------------------------- C. revelations evolved set
print("C. revelations evolved mask set")
evo = [3, 5, 9, 11, 15, 17, 23, 27, 29, 31, 33, 37, 39, 43, 45, 47, 49, 51,
       53, 57, 59, 63, 65, 67, 71, 73, 77, 79, 81, 83, 85, 87, 89, 91, 93, 97,
       99, 101, 103, 105, 107, 111, 115, 117, 119, 121, 125, 127]
check("evolved set == file masks", evo == masks)
n_alias = sum(1 for i, j in combinations(range(48), 2)
              if (d := evo[i] ^ evo[j]) and (d & (d - 1)) == 0)
check("evolved aliases == 96", n_alias == 96, f"got {n_alias}")

print()
if FAILS:
    print(f"FAILED: {len(FAILS)} check(s): {FAILS}")
    sys.exit(1)
print("ALL NEW-MATERIAL CHECKS PASSED")
