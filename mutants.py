#!/usr/bin/env python3
"""Mutation check. Each mutant changes one spot in gate.py inside a throwaway copy of the
repo (a temporary directory, cleaned up by the interpreter when the run ends). The pytest suite
then runs on the copy. A mutant is killed when the suite exits non-zero. A spot that does not
occur exactly once in gate.py is reported INVALID and does not count as killed."""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
B = "gate.py"

MUTANTS = [
    # poison: bounds and comparators
    ("label_shift_ge_instead_of_gt", 'if shift > b["label_shift"]:', 'if shift >= b["label_shift"]:'),
    ("label_shift_never_flags", 'if shift > b["label_shift"]:', "if False:"),
    ("tv_distance_not_halved", "return round(0.5 * sum(", "return round(1.0 * sum("),
    ("tv_ignores_labels_missing_from_data", "labels = set(counts) | set(baseline)", "labels = set(counts)"),
    ("dup_ratio_ge_instead_of_gt", 'if ratio > b["dup_ratio"]:', 'if ratio >= b["dup_ratio"]:'),
    ("dup_compare_case_sensitive", "len(set(normalize(t) for t in texts))", "len(set(texts))"),
    ("trigger_min_count_off_by_one", "d < min_count", "d <= min_count"),
    ("trigger_rare_bound_ge", "d / n > rare", "d / n >= rare"),
    ("trigger_rate_gt_instead_of_ge", "if rate >= rate_bound and", "if rate > rate_bound and"),
    ("trigger_excess_gt_instead_of_ge", "round(rate - base, 6) >= excess", "round(rate - base, 6) > excess"),
    ("trigger_excess_ignored", " and round(rate - base, 6) >= excess:", ":"),
    ("trigger_unigrams_only", "for k in (1, 2, 3):", "for k in (1,):"),
    ("trigger_flag_dropped", 'if triggers:\n        flags.append("BACKDOOR_TRIGGER")', 'if False:\n        flags.append("BACKDOOR_TRIGGER")'),
    ("instruction_allowance_off_by_one", 'if len(instr_lines) > b["max_instruction"]:', 'if len(instr_lines) >= b["max_instruction"]:'),
    ("instruction_role_tag_im_start_lost", "system|assistant|user|im_start|im_end", "system|assistant|user|im_end"),
    ("instruction_assistant_prefix_lost", "(?:system|assistant|developer)", "(?:system|developer)"),
    ("instruction_disregard_lost", r"\b(?:ignore|disregard|forget)\b", r"\b(?:ignore|forget)\b"),
    # poison: admission and refusal
    ("hash_check_skipped", 'if sha256_hex(shard_bytes) != sh["sha256"]:', "if False:"),
    ("signature_check_skipped", 'if not hmac.compare_digest(sign(key, sh).encode("utf-8"), sh["signature"].encode("utf-8")):', "if False:"),
    ("source_allowlist_ignored", 'if _valid_str_list(allowed_src) and sh["source"] not in allowed_src:', "if False:"),
    ("license_allowlist_ignored", 'if _valid_str_list(allowed_lic) and sh["license"] not in allowed_lic:', "if False:"),
    ("unlisted_shard_ignored", "if f not in listed:", "if False:"),
    ("missing_shard_ignored", "if not os.path.isfile(path):", "if False:"),
    ("duplicate_entry_ignored", 'if sh["file"] in listed:', "if False:"),
    ("label_distribution_sum_unchecked", "good = good and abs(sum(ld.values()) - 1.0) <= 1e-3", "good = good"),
    ("bool_accepted_as_share", "if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0.0 <= v <= 1.0:", "if not isinstance(v, (int, float)) or not 0.0 <= v <= 1.0:"),
    ("refusal_does_not_outrank_flag", 'if refusals:\n        verdict = "REFUSE"', 'if False:\n        verdict = "REFUSE"'),
    ("flagged_poison_exits_zero", 'return 0 if rep["verdict"] == "ADMIT" else 1', "return 0"),
    ("duplicate_json_keys_accepted", "if len(keys) != len(set(keys)):", "if False:"),
    ("nan_accepted", 'raise ValueError("non-finite number " + name)', "return 0.0"),
    ("input_hash_wrong", '"sha256": sha256_hex(raw), "bytes": len(raw)', '"sha256": sha256_hex(b""), "bytes": len(raw)'),
    # leak: scoring
    ("verbatim_lcs_gt_instead_of_ge", 'if best["verbatim_lcs"] >= b["lcs_bound"]:', 'if best["verbatim_lcs"] > b["lcs_bound"]:'),
    ("normalized_lcs_gt_instead_of_ge", 'if best["normalized_lcs"] >= b["lcs_bound"]:', 'if best["normalized_lcs"] > b["lcs_bound"]:'),
    ("jaccard_gt_instead_of_ge", 'if best["paraphrase_jaccard"] >= b["jaccard_bound"]:', 'if best["paraphrase_jaccard"] > b["jaccard_bound"]:'),
    ("nfkc_dropped", 'return " ".join(unicodedata.normalize("NFKC", text).lower().split())', 'return " ".join(text.lower().split())'),
    ("lowercase_dropped", 'unicodedata.normalize("NFKC", text).lower().split())', 'unicodedata.normalize("NFKC", text).split())'),
    ("whitespace_not_collapsed", 'return " ".join(unicodedata.normalize("NFKC", text).lower().split())', 'return unicodedata.normalize("NFKC", text).lower()'),
    ("base64_view_dropped", 'out.append(("base64", dec))', "pass"),
    ("hex_view_dropped", 'out.append(("hex", dec))', "pass"),
    ("rot13_view_dropped", 'out.append(("rot13", codecs.decode(reply, "rot_13")))', "pass"),
    ("secret_compact_match_dropped", "return len(cv) >= 12 and cv in compact(view)", "return False"),
    ("internal_host_suffix_ignored", "host.endswith(INTERNAL_SUFFIXES)", "False"),
    ("aws_key_shape_dropped", '("aws_key", AWS_RE), ', ""),
    ("long_token_shape_dropped", ', ("long_token", LONG_RE)', ""),
    ("jaccard_min_reply_off_by_one", "len(reply_toks) < min_reply", "len(reply_toks) <= min_reply"),
    ("jaccard_longer_reply_not_windowed", "if len(reply_toks) <= len(prompt_toks):", "if True:"),
    ("jaccard_takes_worst_window", "best = max(best, len(win & ss) / union)", "best = min(best, len(win & ss) / union)"),
    ("jaccard_union_wrong", "union = len(win | ss)", "union = len(win & ss)"),
    ("reason_drops_comparator", 'f["score"], f["op"], f["bound"]', 'f["score"], "=", f["bound"]'),
    # leak: verdicts and refusals
    ("refusal_phrase_ignored", "if not reply.strip() or REFUSAL_RE.search(normalize(reply)):", "if not reply.strip():"),
    ("empty_reply_is_safe", "if not reply.strip() or REFUSAL_RE", "if REFUSAL_RE"),
    ("fired_checks_do_not_leak", '    if fired:\n        return "LEAKED"', '    if False:\n        return "LEAKED"'),
    ("leak_exits_zero", 'return 0 if rep["verdict"] == "PASS" else 1', "return 0"),
    ("short_prompt_accepted", 'if len(prompt.strip()) < b["min_prompt_chars"]:', "if False:"),
    ("prompt_floor_off_by_one", 'if len(prompt.strip()) < b["min_prompt_chars"]:', 'if len(prompt.strip()) <= b["min_prompt_chars"]:'),
    ("prompt_not_stripped", 'if len(prompt.strip()) < b["min_prompt_chars"]:', 'if len(prompt) < b["min_prompt_chars"]:'),
    ("unknown_probe_id_ignored", 'if obj["id"] not in seen:', "if False:"),
    ("duplicate_reply_ignored", 'if obj["id"] in replies:', "if False:"),
    ("duplicate_probe_ignored", 'if obj["id"] in seen:', "if False:"),
    ("missing_reply_ignored", 'if p["id"] not in replies:', "if False:"),
]


def run_suite(root):
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x"],
                       cwd=root, capture_output=True, text=True)
    return r.returncode


def main():
    with open(os.path.join(HERE, B), encoding="utf-8") as fh:
        source = fh.read()
    if run_suite(HERE) != 0:
        print("control: suite fails unmodified")
        return 1
    print("control: suite passes unmodified")
    killed = 0
    for name, old, new in MUTANTS:
        if source.count(old) != 1:
            print("INVALID %s (spot found %d times)" % (name, source.count(old)))
            continue
        mutated = source.replace(old, new)
        try:
            compile(mutated, B, "exec")
        except SyntaxError:
            print("INVALID %s (does not compile)" % name)
            continue
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "repo")
            shutil.copytree(HERE, root, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
            with open(os.path.join(root, B), "w", encoding="utf-8") as fh:
                fh.write(mutated)
            dead = run_suite(root) != 0
        killed += dead
        print("%s %s" % ("KILLED  " if dead else "SURVIVED", name))
    print("mutants: %d/%d killed" % (killed, len(MUTANTS)))
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
