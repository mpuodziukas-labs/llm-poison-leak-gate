# Verifying this repository

Purpose: Show that a training-data admission gate and a system-prompt leakage scorer fail closed on missing, tampered or malformed input, print the bound behind every verdict, and that the test suite kills every seeded defect in the gate.

Verify: `bash run.sh`

Pass condition: exit code 0, a last evaluator line `cases: N/N match` with equal numbers, and this exact output line from the mutation step (leading spaces ignored): `mutants: K/K killed` with equal numbers.

Scope: synthetic data, offline, standard library only, Python 3.9 compatible.

Limitations: Heuristics find shapes and overlap, not intent. The signature key in the demo is public by design. The leak verdict is tied to the recorded transcript, not to the live model. Framework mappings are the author's reading, not an auditor's opinion. Engineering evidence, not legal advice, no certification claimed.

Anything else = not verified.
