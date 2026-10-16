# swarm

Refusal swarm: verifier genomes, adversarial fuzzing, unanimous-pass judge,
hash-chained ledger — plus the two bots that run it.

## Org

- **swarm-lead** (`bots/swarm_lead.py`) — reports to Jett. Runs the genome
  batteries, collects the judge verdict, verifies the hash-chained ledger,
  verifies the new materials, files a report.
- **flow-overseer** (`bots/flow_overseer.py`) — reports to the swarm-lead.
  Watches ledger tip vs entries, chain integrity, stuck runs.

## Components

- `refusal_swarm.py` — SwarmGate x refusal-pipeline hybrid. Four verifier
  genomes (g-pos, g-sign, g-triple, g-noise), adversarial fuzzing,
  unanimous-pass judge, mutator, hash-chained ledger. Stdlib only.
  `python3 refusal_swarm.py run --target legacy|hardened`
- `agent_gate.py` — AI agent tool-permission admission: per-label headroom,
  non-compensation, adversarial genome, hash-chained verdicts.
- `verify/verify_new_materials.py` — independent recompute of the 2026-10-16
  materials: advanced codec improved instance, H14 evolved matrix,
  revelations evolved set. 27 checks.

## Constitution

Fail-closed. Stdlib only. Measure what is left over after an interaction;
admit only what fits inside that leftover; otherwise refuse and record.
