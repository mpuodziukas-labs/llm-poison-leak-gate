# Inspiration

Public repositories in the same space, with the star counts the GitHub search returned when listed. Descriptions are the search one-liners. No claim is made about their internals, and nothing was copied.

| # | Repository | Stars | Note |
|---|------------|-------|------|
| 1 | promptfoo/promptfoo | 26,685 | LLM evals and red teaming |
| 2 | fivetran/great_expectations | 11,912 | Data validation (owner as returned by the search) |
| 3 | cleanlab/cleanlab | 11,724 | Data-centric label and quality issues |
| 4 | NVIDIA/garak | 9,818 | LLM vulnerability scanner |
| 5 | evidentlyai/evidently | 8,028 | ML and LLM observability |
| 6 | Trusted-AI/adversarial-robustness-toolbox | 6,295 | Adversarial ML library |
| 7 | Giskard-AI/giskard-oss | 5,938 | Testing for ML and LLM systems |
| 8 | microsoft/PyRIT | 4,720 | Risk identification for generative AI |
| 9 | deepchecks/deepchecks | 4,069 | Validation of ML data and models |
| 10 | QData/TextAttack | 3,478 | NLP adversarial attacks and data augmentation |
| 11 | protectai/llm-guard | 3,220 | LLM input and output scanners (archived) |
| 12 | protectai/rebuff | 1,532 | Prompt injection detector (archived) |
| 13 | whylabs/langkit | 1,005 | LLM telemetry and metrics |
| 14 | Giskard-AI/prompt-injections | 37 | Prompt injection samples |

## What ours adds

- Fail-closed admission: a missing field, a missing shard or a signature mismatch is a refusal, not a warning.
- A hash-pinned manifest, with the sha256 of every input read written into the report.
- Bounded leakage scoring: every verdict prints the score, the comparator and the bound it was tested against.
- Mutation-tested: the suite must kill every seeded defect in the gate, and the runner prints the count.
