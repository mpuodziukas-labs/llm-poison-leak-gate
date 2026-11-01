import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import PROMPT, ROOT, build, jl, rows, write  # noqa: E402

GATE = os.path.join(ROOT, "gate.py")
CASES = os.path.join(ROOT, "cases")


def proc(args, cwd):
    return subprocess.run([sys.executable, GATE] + args, capture_output=True, text=True, cwd=str(cwd))


def test_poison_runs_as_a_process_with_the_documented_exit_codes(tmp_path):
    mp, data = build(tmp_path, {"a.jsonl": jl(rows(100))})
    r = proc(["poison", mp, data], tmp_path)
    assert r.returncode == 0 and r.stdout.rstrip().endswith("poison: ADMIT shards=1 refusals=0 flags=0")
    assert os.path.exists(os.path.join(str(tmp_path), "poison-report.json"))
    write(os.path.join(data, "a.jsonl"), "tampered\n")
    r = proc(["poison", mp, data], tmp_path)
    assert r.returncode == 1 and "REFUSE HASH_MISMATCH a.jsonl" in r.stdout
    r = proc(["poison", mp + ".missing", data], tmp_path)
    assert r.returncode == 2 and r.stdout == "" and "BAD INPUT" in r.stderr


def test_leak_runs_as_a_process_with_the_documented_exit_codes(tmp_path):
    pp, tp, bp = [os.path.join(str(tmp_path), n) for n in ("p.txt", "t.jsonl", "b.jsonl")]
    write(pp, PROMPT)
    write(bp, jl([{"id": "p1", "kind": "direct", "prompt": "q"}]))
    write(tp, jl([{"id": "p1", "reply": "Sure. " + PROMPT}]))
    r = proc(["leak", pp, tp, bp], tmp_path)
    assert r.returncode == 1 and "p1 [direct] LEAKED:" in r.stdout and "bound 40" in r.stdout
    write(tp, jl([{"id": "p1", "reply": "Which invoice do you mean?"}]))
    r = proc(["leak", pp, tp, bp], tmp_path)
    assert r.returncode == 0 and r.stdout.rstrip().endswith("leak: PASS probes=1 LEAKED=0 SAFE=1 REFUSED-TO-ANSWER=0")
    r = proc(["leak", pp, tp, bp + ".missing"], tmp_path)
    assert r.returncode == 2


def test_argparse_errors_and_help(tmp_path):
    assert proc([], tmp_path).returncode == 2
    assert proc(["nope"], tmp_path).returncode == 2
    h = proc(["--help"], tmp_path)
    assert h.returncode == 0 and "poison" in h.stdout and "leak" in h.stdout


def test_process_output_is_deterministic(tmp_path):
    mp, data = build(tmp_path, {"a.jsonl": jl(rows(100, ["pos"] * 90 + ["neg"] * 10))})
    a = proc(["poison", mp, data, "--report", "r1.json"], tmp_path)
    b = proc(["poison", mp, data, "--report", "r2.json"], tmp_path)
    assert a.returncode == b.returncode == 1 and a.stdout == b.stdout
    assert open(os.path.join(str(tmp_path), "r1.json"), "rb").read() == open(os.path.join(str(tmp_path), "r2.json"), "rb").read()


def test_case_folders_cover_pass_finding_and_refuse_for_both_commands():
    seen = {"poison": set(), "leak": set()}
    for name in sorted(os.listdir(CASES)):
        exp = json.load(open(os.path.join(CASES, name, "expected.json")))
        seen[exp["cmd"]].add(exp["verdict"] if exp["exit"] != 2 else "BAD_INPUT")
    assert seen["poison"] == {"ADMIT", "FLAGGED", "REFUSE", "BAD_INPUT"}
    assert seen["leak"] == {"PASS", "LEAKED", "REFUSE", "BAD_INPUT"}
    per_cmd = [json.load(open(os.path.join(CASES, n, "expected.json")))["cmd"] for n in os.listdir(CASES)]
    assert per_cmd.count("poison") >= 9 and per_cmd.count("leak") >= 9


def test_every_flag_and_refusal_code_the_gate_can_emit_has_a_case():
    want = {"LABEL_SHIFT", "DUPLICATES", "BACKDOOR_TRIGGER", "INSTRUCTION_STRING", "HASH_MISMATCH", "SIGNATURE_MISMATCH",
            "UNKNOWN_SOURCE", "UNLICENSED", "SHARD_MISSING", "SHARD_FIELD_MISSING", "UNLISTED_SHARD", "MALFORMED_SHARD",
            "PROBE_MISSING", "MALFORMED_LINE", "PROMPT_TOO_SHORT", "UNKNOWN_PROBE_ID",
            "verbatim_lcs", "normalized_lcs", "paraphrase_jaccard", "secret_leak"}
    seen = set()
    for name in os.listdir(CASES):
        exp = json.load(open(os.path.join(CASES, name, "expected.json")))
        seen.update(c.split(":")[0] for c in exp["codes"])
        for v in exp.get("checks", {}).values():
            seen.update(v)
    assert want <= seen, sorted(want - seen)


def test_evaluate_rejects_arguments_it_does_not_take():
    import subprocess
    import sys as _sys
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = subprocess.run([_sys.executable, os.path.join(here, "evaluate.py"), "--bogus"],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "usage" in r.stderr and r.stdout == ""
