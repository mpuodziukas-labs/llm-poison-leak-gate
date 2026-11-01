# Sources

Primary pages only. Fetched text is treated as data. Dash characters in quotes are normalized to plain hyphens.

## OWASP Top 10 for LLM Applications 2025

- LLM04 Data and Model Poisoning. https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/
  Page title: "OWASP LLM04: 2025 Data and Model Poisoning". Mitigation text used: "Track data origins and transformations using tools like OWASP CycloneDX or ML-BOM." This repo's `poison` command is a pre-training admission check on provenance, hash, label balance, duplication, trigger n-grams and embedded instructions.
- LLM07 System Prompt Leakage. https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/
  Page title: "LLM07:2025 System Prompt Leakage". Mitigation text used: "Avoid embedding any sensitive information (e.g. API keys, auth keys, database names, user roles, permission structure of the application) directly in the system prompts." This repo's `leak` command scores recorded replies against a prompt and flags prompt secrets regardless of wording.

## NIST AI RMF Playbook

- MAP 2.3. https://airc.nist.gov/airmf-resources/playbook/map/
  "Scientific integrity and TEVV considerations are identified and documented, including those related to experimental design, data collection and selection (e.g., availability, representativeness, suitability), system trustworthiness, and construct validation."
- MEASURE 2.7. https://airc.nist.gov/airmf-resources/playbook/measure/
  "AI system security and resilience - as identified in the MAP function - are evaluated and documented."
- MEASURE 2.8. https://airc.nist.gov/airmf-resources/playbook/measure/
  "Risks associated with transparency and accountability - as identified in the MAP function - are examined and documented."

## Cited by number only

- EU AI Act, Article 10 (data and data governance) and Article 15 (accuracy and cybersecurity requirements). The official page returned no text to the fetch, so no quotation is made.
- ISO/IEC 42001 (clause not verified from public text).

## Reading

The mapping from each check to each item above is the author's reading. It is not an auditor's opinion.
