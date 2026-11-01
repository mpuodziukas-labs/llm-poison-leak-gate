#!/bin/bash
# One command, whole proof: table, tests, mutants. Exit 0 only if all three pass.
set -uo pipefail
cd "$(dirname "$0")"
/usr/bin/python3 evaluate.py || exit 1
echo
/usr/bin/python3 -m pytest -q -p no:cacheprovider || exit 1
echo
/usr/bin/python3 mutants.py
