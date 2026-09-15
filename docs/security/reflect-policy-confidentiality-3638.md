# Reflection policy diagnostics (#3638)

Governance resolution may read a private standard with internal authority so
that its policy remains enforceable. That authority does not authorize a
requesting tenant to read the standard or values derived from it. The
PostgreSQL `GOVERNANCE_INTERNAL` context and policy resolver permissions are
unchanged.

HTTP and MCP reflection responses expose the refusal category, but not the
resolved depth cap, decorrelation counts/quorum, or private governance reasons.
Substrate hook and database error details are logged and replaced with fixed messages.
SQLite pending-approval responses retain their pending ID and proposed depth,
but omit the resolved approval threshold. Input validation and requested-source
IDs remain public; a title collision does not expose the underlying database
error. Full refusal diagnostics remain in operator logs and existing internal
typed errors/audit records.

This is a response-value confidentiality boundary, not outcome indistinguishability:
refusal, success, and pending approval remain observable. Repeated requests may
still permit inference about policy enforcement. This fix does not change who
can request reflection or resolve a governance policy.

`tests/reflect_policy_confidentiality_3638.rs` exercises authenticated tenant HTTP
requests on SQLite and live PostgreSQL, proves that the tenant cannot read the
victim's private standard, and pins the exact redacted depth refusal. It also
pins SQLite's pending-response threshold omission. The PostgreSQL test requires
`AI_MEMORY_TEST_POSTGRES_URL`; it fails instead of silently skipping when absent.
The issue-numbered unit tests in `src/mcp/tools/reflect.rs` pin all sensitive wire
variants and verify that operator logs retain the attempted depth, cap, and
namespace.
