---
layout: doc
---
# Signed rule packs (refuse-by-default template)

**Status:** v1.0.0 (#1980). Ships the **template + workflow** for an
operator-signed refuse-by-default agent-action rule set. The refuse-by-default
posture is **opt-in** — the substrate does **not** enable it for you. The full
one-file *pack apply* mechanism (a `rules apply-pack` verb + a versioned pack
container + a set-manifest) is deferred to v1.x, to land **with** the
refuse-by-default enforcement consumer (tracked separately — see *Deferred*
below). This doc + [`refuse-by-default-rules.template.json`](./refuse-by-default-rules.template.json)
are the v1.0.0 residue.

## What this is (and is not)

- **Is:** an *illustrative* template rule set + the workflow to sign each rule
  with the operator key (the existing per-rule signing posture, #1961) and
  enable it deliberately.
- **Is not:** a blessed, complete, or prescriptive security policy. The safe
  refusal set is **deployment-specific**. The template's matchers are
  deliberately fake (`*.invalid` hosts, `/example/` paths, `example-*` tools) so
  copying it verbatim refuses **nothing real**. There is no "refuse everything
  dangerous" list — a fixed matcher set cannot deliver the completeness the
  phrase "refuse-by-default" implies (an un-refused escalation path is always
  possible), so **do not** read the template as an attestation of coverage.

## The rule model

An agent-action rule is one row in `governance_rules`
(`docs/governance/agent-action-rules.md` has the full engine + the per-kind
matcher shapes). The signature-bearing fields — the eight covered by the
operator signature — are `id, kind, matcher, severity, reason, namespace,
created_by, enabled`; `created_at`, `attest_level`, and the `signature` itself
are **not** signed and must never be trusted from a file.

Per-kind matcher JSON:

| `kind`             | matcher example                       |
|--------------------|---------------------------------------|
| `filesystem_write` | `{"glob":"/example/forbidden/**"}`    |
| `network_request`  | `{"host":"exfil.example.invalid"}`    |
| `process_spawn`    | `{"binary":"example-forbidden-tool"}` |
| `bash`             | `{"command_substring":"…"}` or `{"command_regex":"…"}` |

## Workflow — activate refuse-by-default (opt-in)

```bash
# 0. Author your policy: copy the template and edit every rule for your
#    deployment (real matchers, real reasons). NEVER ship the example matchers.
cp docs/governance/refuse-by-default-rules.template.json my-rules.json
$EDITOR my-rules.json

# 1. Mint the operator key once (holds the sole authority to sign law).
ai-memory rules keygen

# 2. Sign + install each rule DISABLED (the substrate default is unchanged).
ai-memory rules add \
  --id fs-workspace-only \
  --kind filesystem_write \
  --matcher '{"glob":"/srv/agent-forbidden/**"}' \
  --severity refuse \
  --reason 'no writes outside the agent workspace' \
  --disabled --sign

# 3. Review what will enforce BEFORE activating.
ai-memory rules list

# 4. Enable each reviewed rule (re-signs the enabled state).
ai-memory rules enable fs-workspace-only --sign

# 5. Confirm the installed, enabled set matches your intent.
ai-memory doctor          # runs the policy-version digest drift check
```

Each rule is operator-signed over its canonical bytes and re-verified at
enforcement time; an unverifiable rule is not honored (see
`rules_store::enforced_rule_passes`).

## Honest limits

- **Opt-in, no default flip.** Installing these rules — even enabled — changes
  only the actions your operator chose to refuse. The substrate does **not**
  turn refuse-by-default on globally; there is no compat-breaking default change
  at v1.0.0.
- **Completeness is your responsibility.** The template is a starting point, not
  a covered-everything guarantee.
- **Pin the set out-of-band.** Until the v1.x pack-apply mechanism lands, confirm
  the installed set against a published hash of your reviewed rule file (and the
  `policy_version` digest surfaced by `doctor`) so a dropped or edited rule is
  detectable — per-rule signatures attest each rule's authenticity but not the
  *completeness* of the set.

## Deferred to v1.x

The single-file **pack apply** mechanism — a `rules apply-pack <file>` verb that
verifies an operator-signed **set-manifest** (`{epoch, sorted rule
content-hashes}`, closing the subset/omission + replay gaps that per-rule
signatures alone do not) inside a versioned pack container, and installs every
rule in one atomic transaction — is deferred to v1.x so it lands together with
the refuse-by-default **enforcement** consumer. It will reuse the existing
`epoch-apply` signed-atomic-apply pattern + the `policy_version` set-digest
rather than mint new crypto. Freezing that wire format at v1.0.0 — before its
consumer exists — is the higher-regret path.
