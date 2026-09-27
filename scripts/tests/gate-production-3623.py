#!/usr/bin/env python3
"""Issue #3623: exercise each real gate in an isolated source tree."""
import pathlib
import shutil
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[2]
gates = sys.argv[1:] or ['check-hardcoded-literals.sh', 'check-vendor-literals.sh', 'qc-codegraph-precheck.sh']
failures = 0
count = 0
for gate in gates:
    with tempfile.TemporaryDirectory(prefix='gate-3623-') as tmp:
        tree = pathlib.Path(tmp)
        shutil.copytree(root / 'scripts', tree / 'scripts')
        (tree / 'src').mkdir()
        (tree / 'tools').mkdir()
        if gate == 'check-hardcoded-literals.sh':
            marker = 'production-probe-3623'
            body = '\n'.join(f'pub fn p{i}() {{ consume("{marker}"); }}' for i in range(3))
        elif gate == 'check-vendor-literals.sh':
            marker = '3600'
            body = f'pub fn p() {{ Duration::from_secs({marker}); }}'
        else:
            marker = 'production-probe-3623'
            body = f'pub fn p() {{ CallerContext::for_admin("{marker}"); }}'
        cases = [
            ('attest.rs', body, True),
            ('config.rs', '#[cfg(test)]\nmod tests {\n    fn nested() {}\n}\n' + body, True),
            ('config.rs', '#[cfg(test)]\nmod tests {\n' + '\n'.join('    ' + x for x in body.splitlines()) + '\n}\n', False),
            ('peer_tests.rs', body, False),
            ('test_peer.rs', body, False),
            ('peer_test_helpers.rs', body, False),
            ('peer.rs', '#![cfg(test)]\n' + body, False),
            ('attest_v2.rs', body, True),
            ('peer_attestation.rs', body, True),
            ('attestation.rs', body, True),
            ('model_attest.rs', body, True),
            ('contest.rs', body, True),
            ('config.rs', '#[cfg(test)] mod helper {}\n' + body, True),
            ('config.rs', '#[cfg(all(test, feature = "sal"))]\nmod helper {\n' + '\n'.join('    ' + x for x in body.splitlines()) + '\n}\n', False),
            ('config.rs', '#[cfg(any(test, feature = "sal"))]\nmod helper {\n' + '\n'.join('    ' + x for x in body.splitlines()) + '\n}\n', True),
            ('config.rs', '#[cfg(test)]\nmod helper;\n' + body, True),
            ('config.rs', '#[cfg(test)]\nfn helper() {\n    consume("ignored");\n}\n' + body, True),
        ]
        if gate == 'qc-codegraph-precheck.sh':
            marker = 'GOVERNANCE_INTERNAL'
            site = '            let ctx = CallerContext::for_admin(crate::identity::sentinels::GOVERNANCE_INTERNAL);'
            # #3965/#3970: an allowlist entry is `<file>:<fn>:<literal>:<count>`
            # and licenses exactly <count> sites of <literal> inside <fn>. The
            # allowlist copied into this tree carries (among others)
            # `src/store/postgres.rs:PostgresStore.resolve_governance_policy:GOVERNANCE_INTERNAL:1`,
            # `src/cli/agents.rs:run_bind_api_key:DAEMON_PRINCIPAL:1` +
            # `src/cli/agents.rs:run_revoke_api_key:DAEMON_PRINCIPAL:1`, and
            # `src/handlers/links.rs:create_link:caller:1`. Line position is NOT
            # part of the key (it drifts on every unrelated edit), so a site
            # MOVED within its function is the same reviewed site; a site in a
            # DIFFERENT function is a new key (#3970, the #3638 relocation).
            # The fn key is SCOPE-derived (scripts/tests/c8-enclosing-fn-3970.py):
            # the innermost fn whose body contains the call, qualified by its
            # impl type / outer fns and joined with `.`.
            def in_fn(name, *lines):
                return 'fn ' + name + '() {\n' + '\n'.join(lines) + '\n}'

            def in_pg(*fns):
                return 'impl PostgresStore {\n' + '\n'.join(fns) + '\n}'
            gov_fn = 'resolve_governance_policy'
            # f2r's review of 58a916fa1: one line between a moved site and its
            # real fn re-keyed it under the textual nearest-`fn` rule. Every
            # row must still block; the plain swap is the control.
            spoofs = [
                '    /* fn resolve_governance_policy */',
                '    let _n = 0; // see fn resolve_governance_policy',
                '    let _s = "fn resolve_governance_policy";',
                '    fn resolve_governance_policy() {}',
                '    let _r = r#"fn resolve_governance_policy { "#;',
                "    let _c = '{'; /* nested /* fn resolve_governance_policy */ */",
            ]
            daemon = '    let ctx = CallerContext::for_admin(crate::identity::sentinels::DAEMON_PRINCIPAL);'
            cases = [(name, source, blocked, 'production-probe-3623')
                     for name, source, blocked in cases]
            cases += [
                ('store/postgres.rs', '\n' * 31499 + in_pg(in_fn(gov_fn, site)), False, marker),
                ('store/postgres.rs', '\n' * 31500 + in_pg(in_fn(gov_fn, '', site)), False, marker),
                ('store/postgres.rs', '\n' * 31499 + in_pg(in_fn(gov_fn, site, site)), True, marker),
                ('store/other.rs', '\n' * 31499 + in_pg(in_fn(gov_fn, site)), True, marker),
                ('store/postgres.rs', '\n' * 31499 + in_pg(in_fn(gov_fn, site.replace('GOVERNANCE_INTERNAL', 'DAEMON_PRINCIPAL'))), True, 'DAEMON_PRINCIPAL'),
                # The same fn name OUTSIDE the impl is a different scope.
                ('store/postgres.rs', '\n' * 31499 + in_fn(gov_fn, site), True, gov_fn + ':GOVERNANCE_INTERNAL'),
                # #3970 SWAP: the approved site REMOVED from its function and the
                # same literal added in another function of the same file. The
                # count per file is unchanged; the fn-keyed count is not.
                ('store/postgres.rs', '\n' * 31499 + in_pg(in_fn('tenant_reachable_handler', site)), True, 'PostgresStore.tenant_reachable_handler'),
                # A site in trailing code after the approved fn's body closes is
                # NOT inside it (the textual rule said it was).
                ('store/postgres.rs', '\n' * 31499 + in_pg(in_fn(gov_fn), 'const _X: () = { ' + site.strip() + ' };'), True, '<top>'),
                # A site after a nested helper fn is still in the OUTER fn.
                ('store/postgres.rs', '\n' * 31499 + in_pg(in_fn(gov_fn, '    fn helper() {}', site)), False, marker),
            ]
            cases += [
                ('store/postgres.rs', '\n' * 31499 + in_pg(in_fn(gov_fn), in_fn('execute_pending_action', spoof, site)), True, 'PostgresStore.execute_pending_action')
                for spoof in spoofs
            ]
            cases += [
                ('cli/agents.rs', in_fn('run_bind_api_key', daemon) + '\n' + in_fn('run_revoke_api_key', daemon), False, 'DAEMON_PRINCIPAL'),
                ('cli/agents.rs', in_fn('run_bind_api_key', daemon, daemon) + '\n' + in_fn('run_revoke_api_key', daemon), True, 'DAEMON_PRINCIPAL'),
                # #3965 follow-up (Codex review): an argument the old regexes
                # could not read made the call DISAPPEAR before counting, so a
                # NEW tenant-side site in an approved file passed. Each form
                # below is a NEW site in `create_link`, whose only approved
                # entry is `caller`.
                ('handlers/links.rs', in_fn('create_link', '    let c = CallerContext::for_admin(caller.clone());'), True, 'caller.clone()'),
                ('handlers/links.rs', in_fn('create_link', '    let c = CallerContext::for_admin("ai:review-tenant".to_owned());'), True, 'to_owned()'),
                ('handlers/links.rs', in_fn('create_link', '    let c = CallerContext::for_admin(', '        make_caller(a, b),', '    );'), True, 'make_caller'),
                ('handlers/links.rs', in_fn('create_link', '    let c = CallerContext::for_admin('), True, '<unparsed>'),
                # Control: the ONE approved `caller` site in `create_link` stays
                # clean, so the cells above are not passing by blocking everything.
                ('handlers/links.rs', in_fn('create_link', '    let c = CallerContext::for_admin(&caller);'), False, 'caller'),
                # #3970 SWAP on the tenant surface: the approved `caller` site
                # moved into ANOTHER handler of the same file.
                ('handlers/links.rs', in_fn('get_links', '    let c = CallerContext::for_admin(&caller);'), True, 'get_links'),
            ]
        else:
            cases = [(name, source, blocked, marker) for name, source, blocked in cases]
        for i, (name, source, blocked, marker) in enumerate(cases):
            path = tree / 'src' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source + '\n')
            run = subprocess.run(['bash', str(tree / 'scripts' / gate)], capture_output=True, text=True)
            path.unlink()
            output = run.stdout + run.stderr
            ok = (run.returncode == 1 and marker in output) if blocked else run.returncode == 0
            count += 1
            failures += not ok
            print(f'{"PASS" if ok else "FAIL"} #3623 {gate} case {i + 1}: {name} expected {"blocked" if blocked else "clean"}', flush=True)
            if not ok:
                print(output)
print(f'#3623: {count} tests, {failures} failures')
sys.exit(bool(failures))
