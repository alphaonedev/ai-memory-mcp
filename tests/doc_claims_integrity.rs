// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cargo test` twin of the CERT-GATE-2 published-claims gates
//! (#2629 / #2492; 3x7 claims register
//! `docs/audit/3x7-claims-register-2026-08-01.md` 3.3).
//!
//! WHY A TWIN EXISTS. The four shell gates
//! (`scripts/check-docs-vs-ssot.sh`,
//! `scripts/check-doc-symbol-anchors.sh`,
//! `scripts/check-sdk-route-paths.sh`,
//! `scripts/check-ci-job-claims.sh`) all live in ONE workflow. A
//! deleted job, a renamed script, or a `paths:` filter would make every
//! one of them silently stop running while the branch stayed green —
//! which is the exact `#2444` "reports success while doing nothing"
//! shape the register says is worse than a missing control. The
//! `tests/migration_ladder_integrity.rs` precedent answers that by
//! re-asserting the invariants where `cargo test` can see them, and
//! this file does the same for the claims surface.
//!
//! SCOPE, deliberately: the two invariants with a concrete RUNTIME
//! consequence (an SDK method that 404s; a doc naming a CI job that
//! does not exist), plus the two STRUCTURAL properties that keep the
//! shell gates honest (their ledgers parse; they are wired into CI with
//! their self-tests). The full pattern sets stay in the shell gates —
//! duplicating those in Rust would create two definitions that can
//! disagree, and a gate whose twin disagrees with it teaches reviewers
//! to ignore both.
//!
//! Run: `( umask 022; cargo test --test doc_claims_integrity )`
//! (the bare `cargo test` umask trap is #2628).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Collapse every path-PARAMETER segment to `{}`.
///
/// `{id}`, `{memory_id}`, `:id`, `${encodeURIComponent(id)}` and `<id>`
/// all mean "one caller-supplied segment", so they must compare equal;
/// everything else is a literal segment and must match verbatim. This
/// is the step that makes the check catch C-20 (a wrong-SHAPE path
/// against a registered COLLECTION path) rather than only C-19.
fn normalise_path(raw: &str) -> String {
    let head = raw.split(['?', '#']).next().unwrap_or(raw);
    let head = head.trim_end_matches(['/', '.', ',', ';', ':', ')', '*', '`', '"', '\'']);
    head.split('/')
        .map(|seg| {
            let is_param = (seg.starts_with('{') && seg.ends_with('}'))
                || (seg.starts_with("${") && seg.ends_with('}'))
                || (seg.starts_with('<') && seg.ends_with('>'))
                || (seg.starts_with(':') && seg.len() > 1);
            if is_param { "{}" } else { seg }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Keep only the CALL-SITE lines of an SDK file.
///
/// A raw-text scan fails on the CORRECTED tree, not the broken one: the
/// C-19/C-20 fix deletes the dead methods but its BREAKING-CHANGE notes
/// NAME the dead paths in order to explain them (`// cluster() was
/// REMOVED at v1.0.0. It posted to /api/v1/cluster ...`, a docstring
/// narrating the old `unsubscribe` shape, a README migration
/// paragraph). Failing those would force the removal notes to be
/// deleted — and the migration note is the thing that stops an
/// integrator re-adding the method. So comments, docstrings and prose
/// are out of scope BY CONSTRUCTION. This mirrors
/// `scripts/check-sdk-route-paths.sh`; the two are checked against each
/// other by both being run on the same tree.
fn call_site_lines(path: &Path, text: &str) -> Vec<(usize, String)> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let is_md = name.ends_with(".md");
    let is_py = name.ends_with(".py");
    let mut out = Vec::new();
    let mut fenced = false;
    let mut docstring: Option<&str> = None;
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if is_md {
            if trimmed.starts_with("```") {
                fenced = !fenced;
                continue;
            }
            if fenced || trimmed.starts_with('|') {
                out.push((idx + 1, line.to_string()));
            }
            continue;
        }
        if is_py {
            if let Some(fence) = docstring {
                if line.contains(fence) {
                    docstring = None;
                }
                continue;
            }
            if trimmed.starts_with('#') {
                continue;
            }
            let opener = ["\"\"\"", "'''"]
                .into_iter()
                .filter(|q| line.contains(q))
                .min_by_key(|q| line.find(q).unwrap_or(usize::MAX));
            if let Some(q) = opener {
                let (head, rest) = line.split_once(q).unwrap_or((line, ""));
                if !rest.contains(q) {
                    docstring = Some(q);
                }
                out.push((idx + 1, head.to_string()));
                continue;
            }
            let code = line.split('#').next().unwrap_or(line);
            out.push((idx + 1, code.to_string()));
            continue;
        }
        // .ts / .js: line comments and JSDoc continuations carry the
        // removal notes; the call sites never start with them.
        if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
            continue;
        }
        out.push((idx + 1, line.to_string()));
    }
    out
}

/// Every `/api/v1/...` literal on a line, with `${...}` consumed whole
/// so a TS template expression containing `(` or `)` stays one segment.
fn extract_api_paths(line: &str) -> Vec<String> {
    const MARKER: &str = "/api/v1/";
    let bytes: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(rel) = line[i..].find(MARKER) {
        let start = i + rel;
        let mut j = start + MARKER.len();
        let chars_start = line[..j].chars().count();
        let mut k = chars_start;
        while k < bytes.len() {
            if bytes[k] == '$' && bytes.get(k + 1) == Some(&'{') {
                while k < bytes.len() && bytes[k] != '}' {
                    k += 1;
                }
                k += 1;
                continue;
            }
            if matches!(
                bytes[k],
                ' ' | '"' | '\'' | '`' | ')' | ']' | '|' | ',' | ';' | '<' | '>' | '\t'
            ) {
                break;
            }
            k += 1;
        }
        let piece: String = bytes[chars_start.min(bytes.len())..k.min(bytes.len())]
            .iter()
            .collect();
        out.push(format!("{MARKER}{piece}"));
        j = j.max(start + MARKER.len());
        i = j;
    }
    out
}

/// `<file>|<key>` ledger entries, with everything after the first `#`
/// treated as commentary. `strict_arity` mirrors each gate's own parse:
/// the SDK ledger is exactly two whitespace-separated fields, the CI
/// one is a file plus a token that may contain spaces.
fn load_ledger(path: &Path, two_field: bool) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if !path.exists() {
        return out;
    }
    for raw in read(path).lines() {
        let entry = raw.split('#').next().unwrap_or("").trim();
        if entry.is_empty() {
            continue;
        }
        assert!(
            raw.contains('#')
                && raw
                    .split('#')
                    .nth(1)
                    .is_some_and(|t| t.starts_with(|c: char| c.is_ascii_digit())),
            "{}: entry must cite an issue as `#<number>`: {raw}",
            path.display()
        );
        let mut parts = entry.split_whitespace();
        let file = parts.next().unwrap_or_default();
        let rest: Vec<&str> = parts.collect();
        assert!(
            !file.is_empty() && !rest.is_empty(),
            "{}: malformed entry: {raw}",
            path.display()
        );
        if two_field {
            assert_eq!(
                rest.len(),
                1,
                "{}: expected `<file> <token> #<issue>`: {raw}",
                path.display()
            );
        }
        out.insert(format!("{file}|{}", rest.join(" ")));
    }
    out
}

// ---------------------------------------------------------------------
// 1. SDK path literals vs the routes.rs SSOT (register 3.3.2)
// ---------------------------------------------------------------------

/// The invariant with a runtime consequence: a shipped SDK method that
/// names an unregistered path 404s at the customer's first call. C-19
/// put three of those in BOTH SDKs; C-20 put a wrong-SHAPE fourth in
/// TypeScript.
#[test]
fn sdk_route_paths_resolve_against_routes_rs_2629() {
    let root = repo_root();
    let routes_rs = root.join("src/handlers/routes.rs");
    assert!(routes_rs.exists(), "routes.rs SSOT missing: {routes_rs:?}");

    let mut registered: BTreeSet<String> = BTreeSet::new();
    for line in read(&routes_rs).lines() {
        let Some(rest) = line.split("&str = \"").nth(1) else {
            continue;
        };
        if !line.trim_start().starts_with("pub const") {
            continue;
        }
        if let Some(path) = rest.split('"').next().filter(|p| p.starts_with('/')) {
            registered.insert(normalise_path(path));
        }
    }
    assert!(
        registered.len() > 50,
        "routes.rs yielded only {} path consts — the extraction is broken, and a broken \
         extraction would make this test pass by knowing nothing",
        registered.len()
    );

    let ledger = load_ledger(
        &root.join("scripts/qc-allowlists/sdk-route-paths-pending.txt"),
        true,
    );

    let mut sdk_files: Vec<PathBuf> = Vec::new();
    collect_files(&root.join("sdk"), &mut sdk_files);
    assert!(
        !sdk_files.is_empty(),
        "scanned zero sdk files — the gate would be a no-op"
    );

    let mut violations: Vec<String> = Vec::new();
    let mut used: BTreeSet<String> = BTreeSet::new();
    for file in &sdk_files {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        let text = read(file);
        for (ln, line) in call_site_lines(file, &text) {
            for raw in extract_api_paths(&line) {
                let norm = normalise_path(&raw);
                if norm == "/api/v1" || norm == "/api/v1/" || registered.contains(&norm) {
                    continue;
                }
                let key = format!("{rel}|{norm}");
                if ledger.contains(&key) {
                    used.insert(key);
                    continue;
                }
                violations.push(format!(
                    "{rel}:{} targets {raw} (normalised {norm})",
                    ln + 1
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "SDK paths that are not registered routes:\n  {}",
        violations.join("\n  ")
    );

    // A STALE pending-fix entry is reported, never asserted on: the SDK
    // correction lane and this gate land independently, and failing on
    // the race would red whichever PR lost it. The shell gate emits the
    // same NOTICE.
    for key in ledger.difference(&used) {
        println!("NOTICE: stale sdk-route-paths ledger entry (delete it): {key}");
    }
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if path.is_dir() {
            if name == "node_modules" || name == "__tests__" || name == "tests" {
                continue;
            }
            collect_files(&path, out);
        } else {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase);
            if name == "README.md" || matches!(ext.as_deref(), Some("ts" | "py" | "js")) {
                out.push(path);
            }
        }
    }
}

// ---------------------------------------------------------------------
// 2. Named CI jobs cited in docs must exist (register 3.3.3)
// ---------------------------------------------------------------------

/// C-24's shape, in Rust: a doc naming `<workflow>.yml`'s "<Job>" job
/// must name a job that workflow actually declares. The "Code Coverage"
/// job was removed in #1993 and both README and ROADMAP still cite it.
#[test]
fn named_ci_jobs_cited_in_docs_exist_2629() {
    let root = repo_root();
    let wf_dir = root.join(".github/workflows");
    let mut per_workflow: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    let entries = fs::read_dir(&wf_dir).expect("read .github/workflows");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }
        let base = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let mut jobs: BTreeSet<String> = BTreeSet::new();
        let mut in_jobs = false;
        for line in read(&path).lines() {
            if line.trim_end() == "jobs:" {
                in_jobs = true;
                continue;
            }
            if in_jobs && !line.is_empty() && !line.starts_with(' ') {
                in_jobs = false;
            }
            if !in_jobs {
                continue;
            }
            if let Some(key) = line
                .strip_prefix("  ")
                .and_then(|l| l.strip_suffix(':'))
                .filter(|k| !k.is_empty() && !k.starts_with(' '))
            {
                jobs.insert(key.to_string());
            }
            if let Some(raw) = line.strip_prefix("    name:") {
                jobs.insert(yaml_scalar(raw));
            }
        }
        per_workflow.insert(base, jobs);
    }
    assert!(
        per_workflow.len() > 5,
        "parsed only {} workflows — the extraction is broken",
        per_workflow.len()
    );

    let ledger = load_ledger(
        &root.join("scripts/qc-allowlists/ci-job-claims-pending.txt"),
        false,
    );

    let docs = ["README.md", "ROADMAP.md", "PERFORMANCE.md"];
    let mut violations = Vec::new();
    let mut used: BTreeSet<String> = BTreeSet::new();
    for doc in docs {
        let path = root.join(doc);
        if !path.exists() {
            continue;
        }
        for (ln, line) in read(&path).lines().enumerate() {
            for (wf, job) in possessive_job_citations(line) {
                let Some(jobs) = per_workflow.get(&wf) else {
                    continue;
                };
                if jobs.contains(&job) {
                    continue;
                }
                let key = format!("{doc}|{wf}:{job}");
                let bare = format!("{doc}|{job}");
                if ledger.contains(&key) {
                    used.insert(key);
                    continue;
                }
                if ledger.contains(&bare) {
                    used.insert(bare);
                    continue;
                }
                violations.push(format!("{doc}:{} cites {wf}'s \"{job}\" job", ln + 1));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "docs citing CI jobs that do not exist:\n  {}",
        violations.join("\n  ")
    );
    for key in ledger.difference(&used) {
        println!("NOTICE: unexercised ci-job-claims ledger entry: {key}");
    }
}

/// The real YAML scalar rule: a `#` PRECEDED BY WHITESPACE opens a
/// comment, so an unquoted `name: Foo #123` is really `Foo`, while
/// `(#1174 PR10)` is not a comment. This is the #2473 rule, and the
/// reason it matters here is that a doc citing the UNTRUNCATED name
/// must still resolve.
fn yaml_scalar(raw: &str) -> String {
    let raw = raw.trim();
    for quote in ['"', '\''] {
        if let Some(inner) = raw
            .strip_prefix(quote)
            .and_then(|rest| rest.split(quote).next())
            .filter(|_| raw.matches(quote).count() >= 2)
        {
            return inner.to_string();
        }
    }
    let bytes: Vec<char> = raw.chars().collect();
    for i in 1..bytes.len() {
        if bytes[i] == '#' && bytes[i - 1].is_whitespace() {
            return raw.chars().take(i).collect::<String>().trim().to_string();
        }
    }
    raw.to_string()
}

/// The `` `<wf>.yml`'s "<Name>" job `` citation grammar — the exact
/// shape ROADMAP.md uses for the removed "Code Coverage" job.
fn possessive_job_citations(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(idx) = rest.find(".yml`'s ") {
        let (head, tail) = rest.split_at(idx);
        let Some(wf_start) = head.rfind('`') else {
            rest = &tail[8..];
            continue;
        };
        let wf = format!("{}.yml", &head[wf_start + 1..]);
        let after = &tail[".yml`'s ".len()..];
        let name = after
            .strip_prefix('"')
            .and_then(|s| s.split('"').next())
            .or_else(|| after.strip_prefix('`').and_then(|s| s.split('`').next()));
        if let Some(name) = name {
            // The trailing `job` keyword is REQUIRED, so `ci.yml`'s
            // "Code Coverage" **step** (or any other possessive that is
            // not a job citation) is not mistaken for one.
            let follows = after[after.find(name).map_or(0, |i| i + name.len())..].trim_start();
            if follows.starts_with("\" job") || follows.starts_with("` job") {
                out.push((wf, name.to_string()));
            }
        }
        rest = after;
    }
    out
}

// ---------------------------------------------------------------------
// 3. Structural: the gates cannot be silently unwired
// ---------------------------------------------------------------------

/// Every claims gate must exist, be wired into `c8-precheck.yml`, AND
/// carry a `--self-test` step there. The self-test requirement is the
/// load-bearing half: a gate whose detection logic silently stops
/// detecting is precisely the #2444 shape, and running the gate without
/// running its self-test would not notice.
#[test]
fn claims_gates_are_wired_into_ci_with_self_tests_2629() {
    let root = repo_root();
    // CRLF-NORMALISED. The assertions below anchor on `\n` to distinguish a
    // real `run: bash <script>` invocation from a mention inside a longer
    // command, and git on Windows checks this file out with CRLF, so an
    // un-normalised `contains("bash …sh\n")` fails on `Check
    // (windows-latest)` ONLY -- green on ubuntu + macOS, red on the one
    // runner nobody reads first. A gate's own twin must not be
    // platform-dependent.
    let workflow = read(&root.join(".github/workflows/c8-precheck.yml")).replace("\r\n", "\n");
    for script in [
        "scripts/check-docs-vs-ssot.sh",
        "scripts/check-doc-symbol-anchors.sh",
        "scripts/check-sdk-route-paths.sh",
        "scripts/check-ci-job-claims.sh",
    ] {
        let path = root.join(script);
        assert!(path.exists(), "claims gate missing from the tree: {script}");
        assert!(
            workflow.contains(&format!("bash {script}\n")),
            "{script} is not invoked by c8-precheck.yml — the gate would never run in CI"
        );
        assert!(
            workflow.contains(&format!("bash {script} --self-test")),
            "{script} has no --self-test step in c8-precheck.yml; a gate whose detection \
             logic silently stops detecting reports success while doing nothing"
        );
    }

    // R-203 for the normalisation itself: prove a CRLF checkout really
    // WOULD have failed the un-normalised predicate, so this is a live
    // guard rather than a defensive `.replace` nobody can justify. The
    // `Check (windows-latest)` leg of PR #2659 failed on exactly this.
    let crlf = workflow.replace('\n', "\r\n");
    let probe = "bash scripts/check-docs-vs-ssot.sh\n";
    assert!(
        !crlf.contains(probe),
        "the CRLF simulation did not reproduce the windows-latest failure; \
         this leg is broken, not the normalisation"
    );
    assert!(
        crlf.replace("\r\n", "\n").contains(probe),
        "normalisation failed to recover the match on a CRLF checkout"
    );

    // None of the four may be made conditional. A gate policing the
    // docs-only short-circuit must not be subject to it (the #2494
    // rules (b1)/(b4)/(c)/(d)/(e) argument).
    //
    // COMMENT LINES ARE STRIPPED FIRST. This workflow's own prose
    // explains why it carries no `needs: classify`, and a naive
    // substring test would fire on the explanation — a control that
    // fails on the sentence describing it is not enforcing anything.
    let code: String = workflow
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("needs: classify"),
        "c8-precheck.yml acquired a `needs: classify` — the claims gates must stay unconditional"
    );
    assert!(
        !code.contains("\n    paths:"),
        "c8-precheck.yml acquired a `paths:` filter — that wedges every context it carries"
    );
    assert!(
        !code.lines().any(|l| l.starts_with("    if:")),
        "c8-precheck.yml acquired a job-level `if:` — a skipped required context counts as \
         SATISFIED, so the claims gates must never be skippable"
    );
}

/// Every ledger parses under its own gate's rules. A ledger that has
/// rotted into prose is a suppression nobody can audit, so the twin
/// asserts the format even when the shell gate is bypassed.
#[test]
fn claims_gate_ledgers_are_well_formed_2629() {
    let root = repo_root();
    let two_field = [
        "scripts/qc-allowlists/sdk-route-paths-pending.txt",
        "scripts/qc-allowlists/doc-symbol-anchors-allow.txt",
    ];
    let free_form = [
        "scripts/qc-allowlists/ci-job-claims-pending.txt",
        "scripts/qc-allowlists/doc-numeric-claims-pending.txt",
    ];
    for rel in two_field {
        let entries = load_ledger(&root.join(rel), true);
        println!("{rel}: {} entries", entries.len());
    }
    for rel in free_form {
        let entries = load_ledger(&root.join(rel), false);
        println!("{rel}: {} entries", entries.len());
    }

    // The numeric-claims ledger's third field is the CLAIMED value, and
    // it must never equal the canonical — an entry that suppresses the
    // CORRECT value would silence a rule permanently.
    let src_lib = read(&root.join("src/lib.rs"));
    let canonical_routes = src_lib
        .lines()
        .find_map(|l| {
            l.split("EXPECTED_PRODUCTION_ROUTES_COUNT: usize = ")
                .nth(1)
                .and_then(|t| t.split(';').next())
        })
        .expect("EXPECTED_PRODUCTION_ROUTES_COUNT not found in src/lib.rs")
        .trim()
        .to_string();
    for key in load_ledger(
        &root.join("scripts/qc-allowlists/doc-numeric-claims-pending.txt"),
        false,
    ) {
        let parts: Vec<&str> = key.split(['|', ' ']).collect();
        if parts.len() >= 3 && parts[1] == "EXPECTED_PRODUCTION_ROUTES_COUNT" {
            assert_ne!(
                parts[2], canonical_routes,
                "ledger entry suppresses the CANONICAL route count ({canonical_routes}); \
                 that would silence the rule forever: {key}"
            );
        }
    }
}
