**Retire unsupported provider aliases.** Four provider aliases are no longer
accepted as a backend selector on any surface: `AI_MEMORY_LLM_BACKEND`,
`AI_MEMORY_EMBED_BACKEND`, `[llm].backend`, `[embeddings].backend`,
`[llm.auto_tag].backend`, a backend passed on the command line, and the
`ai-memory doctor` LLM section. Their default base URLs, default models,
API-key environment-variable fallbacks and model-family stem are removed, and
the provider-name gate (`scripts/ci/check_no_cn_ai_vendor.py`) now exempts no
functional code (`functional_code_sites` is empty). The documented alias count
is reconciled to 12 vendor aliases plus `openai-compatible` and native Ollama.

**What it costs you.** A configuration that names one of the retired aliases,
in any case and with or without surrounding white space, is refused fail
closed with the standard unknown-selector error; there is no fallback to
another provider and no default base URL is filled in:

```text
LLM backend `<selector>` is not a recognized backend alias. Valid values: ollama, openai-compatible, openai, xai, anthropic, gemini, mistral, groq, together, cerebras, openrouter, fireworks, lmstudio, vllm
```

New loader attestations for models of the retired families, served through
any backend, record no family (the memory stays CLAIMED); existing rows are
not rewritten.

**Remedy.** Choose one of the listed selectors, or, for an endpoint that
speaks the OpenAI wire format, set the selector to `openai-compatible` with an
explicit base URL (`AI_MEMORY_LLM_BASE_URL` / `[llm].base_url`, and
`AI_MEMORY_EMBED_BASE_URL` / `[embeddings].base_url` for embeddings). See the
upgrade note in `docs/MIGRATION_QUICKSTART.md`.
