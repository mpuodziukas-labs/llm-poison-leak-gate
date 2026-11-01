#!/usr/bin/env python3
"""Run gate.py over every case in cases/ and compare with the hand-written expected.json.
A crash is a mismatch, never a pass. Writes PROOF.json. All case data is synthetic."""
import contextlib
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")
sys.path.insert(0, HERE)
import gate  # noqa: E402


def observed(exp, folder, tmp):
    """Run the gate for one case and return the comparable summary."""
    report = os.path.join(tmp, "report.json")
    if exp["cmd"] == "poison":
        argv = ["poison", os.path.join(folder, "manifest.json"), os.path.join(folder, "data"), "--report", report]
    else:
        argv = ["leak", os.path.join(folder, "system_prompt.txt"), os.path.join(folder, "transcript.jsonl"),
                os.path.join(folder, "probes.jsonl"), "--report", report]
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc = gate.main(argv)
    if rc == 2:
        wrote = os.path.exists(report)
        out = {"exit": 2, "verdict": None, "codes": [], "wrote_report": wrote}
        if exp["cmd"] == "leak":
            out.update({"probes": {}, "checks": {}})
        return out
    with open(report, encoding="utf-8") as fh:
        rep = json.load(fh)
    inputs_ok = all(len(i["sha256"]) == 64 for i in rep["inputs"]) and len(rep["inputs"]) > 0
    if exp["cmd"] == "poison":
        codes = sorted(set(["%s:%s" % (r["code"], r["shard"]) for r in rep["refusals"]] +
                           ["%s:%s" % (f["code"], f["shard"]) for f in rep["flags"]]))
        return {"exit": rc, "verdict": rep["verdict"], "codes": codes, "inputs_hashed": inputs_ok}
    probes = dict((p["id"], p["verdict"]) for p in rep["probes"])
    checks = dict((p["id"], sorted(p["fired"])) for p in rep["probes"] if p["fired"])
    codes = sorted(set(r["code"] for r in rep["refusals"]))
    return {"exit": rc, "verdict": rep["verdict"], "probes": probes, "checks": checks, "codes": codes,
            "inputs_hashed": inputs_ok}


def run_case(name):
    """Return (want_text, got_text, ok)."""
    folder = os.path.join(CASES, name)
    try:
        with open(os.path.join(folder, "expected.json"), encoding="utf-8") as fh:
            exp = json.load(fh)
        want = {"exit": exp["exit"], "verdict": exp["verdict"], "codes": sorted(exp["codes"])}
        if exp["cmd"] == "leak":
            want["probes"] = exp["probes"]
            want["checks"] = exp["checks"]
    except (OSError, ValueError, KeyError) as exc:
        return "unreadable expected.json", "ERROR " + type(exc).__name__, False
    try:
        with tempfile.TemporaryDirectory() as tmp:
            got = observed(exp, folder, tmp)
    except Exception as exc:  # noqa: BLE001
        return json.dumps(want, sort_keys=True), "ERROR " + type(exc).__name__, False
    ok = True
    for key, val in want.items():
        if got.get(key) != val:
            ok = False
    if exp["exit"] != 2 and not got.get("inputs_hashed"):
        ok = False
    if exp["exit"] == 2 and got.get("wrote_report"):
        ok = False
    shown = dict((k, got[k]) for k in want if k in got)
    return json.dumps(want, sort_keys=True), json.dumps(shown, sort_keys=True) + ("" if ok else " MISMATCH"), ok


def main():
    names = sorted(n for n in os.listdir(CASES) if os.path.isdir(os.path.join(CASES, n)))
    rows, matched = [], 0
    print("| case | expected | got | match |")
    print("|---|---|---|---|")
    for n in names:
        want, got, ok = run_case(n)
        matched += ok
        rows.append({"case": n, "expected": want, "got": got, "match": ok})
        print("| %s | %s | %s | %s |" % (n, want, got, "yes" if ok else "NO"))
    with open(os.path.join(HERE, "PROOF.json"), "w", encoding="utf-8") as fh:
        json.dump({"matched": matched, "total": len(names), "cases": rows}, fh, indent=2)
        fh.write("\n")
    print()
    print("cases: %d/%d match" % (matched, len(names)))
    return 0 if names and matched == len(names) else 1


if __name__ == "__main__":
    sys.exit(main())
