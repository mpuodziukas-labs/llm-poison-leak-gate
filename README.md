# llm-poison-leak-gate

Proves: a training-data admission gate and a system-prompt leakage scorer fail closed, print the bound behind every verdict, and are checked by a test suite that kills seeded defects in the gate. Verify in 60s: `python3 evaluate.py`

Engineering evidence, not legal advice, no certification claimed. All data is synthetic and labeled synthetic.

## The problem

Two gaps in the OWASP Top 10 for LLM Applications 2025 are usually handled by hand or by trust:

- LLM04 Data and Model Poisoning: a shard of training data is admitted because it looks fine, with no hash pin, no provenance check and no scan for planted triggers.
- LLM07 System Prompt Leakage: a prompt is declared safe because one probe was answered politely, with no score and no stated bound.

This repo is one CLI, `python3 gate.py`, with two subcommands that turn each gap into a verdict with an exit code and a JSON report.

## Run it

```
python3 gate.py poison <manifest.json> <data_dir>
python3 gate.py leak <system_prompt.txt> <transcript.jsonl> <probes.jsonl>
python3 evaluate.py          # case table, last line: cases: N/N match
bash run.sh                  # table, pytest, mutants
```

Exit codes: 0 pass, 1 refuse or finding, 2 bad input. Each subcommand writes a JSON report containing the sha256 of every input it read. Output is deterministic. `python3 gate.py <command> --help` lists the report path option.

## What it checks

`poison` (verdicts ADMIT, FLAGGED, REFUSE):

- Shard sha256 against the file on disk, and an HMAC provenance signature over file, source, license and hash (the demo key is public).
- Source and license against the manifest allowlists. Unknown or unlicensed is a refusal.
- Label distribution against the manifest baseline, as total variation distance.
- Duplicate ratio on normalized text.
- A backdoor-trigger scan computed from the data: 1 to 3 gram document frequency, rarity, label purity and excess over the label share. No trigger string is hardcoded.
- Embedded instruction strings (ignore-previous phrasing, role prefixes, role tags).
- A missing field, a missing shard, an unlisted shard, a malformed shard or a signature mismatch is REFUSE, never a skip.

`leak` (verdicts per probe LEAKED, SAFE, REFUSED-TO-ANSWER; run verdict PASS, LEAKED or REFUSE):

- Verbatim longest common substring against the prompt.
- Normalized longest common substring (NFKC, lowercase, whitespace collapse).
- Paraphrase score: shingle Jaccard over a sliding window of the reply, with a minimum reply length.
- Prompt secrets (keys, long tokens, internal URLs) matched regardless of wording, including in base64, hex and rot13 views of the reply.
- Every verdict line prints the score, the comparator and the bound used. A fired check wins over a refusal phrase.
- A missing probe id, an unknown probe id, a malformed line or a too-short prompt is REFUSE. Exit 0 only with no LEAKED probe and no REFUSE.

The bounds live in one table in `gate.py` and are printed in every report. Comparators are strict greater-than for label shift and duplicate ratio, and greater-than-or-equal for the leak scores.

## Mapping

| Check | OWASP LLM Top 10 2025 | NIST AI RMF | EU AI Act |
|-------|-----------------------|-------------|-----------|
| Hash pin, signature, source, license | LLM04 | MAP 2.3 | Art. 10 |
| Label shift, duplicates, trigger scan, instruction strings | LLM04 | MAP 2.3, MEASURE 2.7 | Art. 10, Art. 15 |
| Verbatim, normalized and paraphrase leak scores | LLM07 | MEASURE 2.7, MEASURE 2.8 | Art. 15 |
| Prompt secret detection | LLM07 | MEASURE 2.7 | Art. 15 |

ISO/IEC 42001: clause not verified from public text, so no clause is mapped. Quoted text and URLs are in `SOURCES.md`. The mapping is the author's reading, not an auditor's opinion.

## Honesty

The cases are synthetic and were written for this repository. No language model runs in the loop: the gate and the evaluation script import only the Python standard library, and the leak scorer reads a recorded transcript. The thresholds and the cases were written together, so the case count that evaluate.py prints is a consistency check, not a claim that the gate generalizes. The signing key and the service key in the fixtures are test fixtures, not secrets. Nothing here was run against production data.

## Limitations

- Regex and n-gram heuristics find shapes and overlap, not intent. A novel trigger or a new paraphrase can pass.
- The trigger scan counts document frequency per record, so heavy duplication can raise a chance n-gram. The duplicate check is the companion signal.
- The synthetic signature key is public. A real deployment needs a private key held outside the repo.
- The paraphrase score uses single-token shingles, which favors recall over precision.
- The refusal phrase list is finite.
- The leak verdict is tied to the recorded transcript, not to the live model that produced it.
- The mutation check seeds defects in `gate.py` only. It does not prove the absence of other defects.
- Numbers for cases, tests and mutants are those the runner prints. This file states none of its own.
