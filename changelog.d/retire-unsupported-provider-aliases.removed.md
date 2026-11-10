**Retire unsupported provider aliases.** Four provider aliases are no longer
accepted as `AI_MEMORY_LLM_BACKEND`, `[llm].backend` or `[embeddings].backend`
values. Selecting one is refused fail closed with the standard
unknown-selector error, which lists the 14 accepted values; there is no
fallback to another provider. Their default base URLs, default models,
API-key environment-variable fallbacks and model-family stem are removed, and
the provider-name gate (`scripts/ci/check_no_cn_ai_vendor.py`) now exempts no
functional code (`functional_code_sites` is empty). The documented alias count
is reconciled to 12 vendor aliases plus `openai-compatible` and native Ollama.
