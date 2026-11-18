#!/bin/bash
# One command, whole proof: table, tests, mutants. Exit 0 only if all three pass.
set -uo pipefail
cd "$(dirname "$0")"
"${PYTHON:-python3}" evaluate.py || exit 1
echo
"${PYTHON:-python3}" -m pytest -q -p no:cacheprovider || exit 1
echo
"${PYTHON:-python3}" mutants.py
