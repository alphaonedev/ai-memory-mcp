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
            # #4054: an UNDECLARED test-named file is production (fail
            # closed); the declared cfg(test) forms are in decl_cases below.
            ('peer_tests.rs', body, True),
            ('test_peer.rs', body, True),
            ('peer_test_helpers.rs', body, True),
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
        # #4054: a test-looking FILE NAME proves nothing; only a cfg(test)
        # DECLARATION does. Each case below carries its declaring parent(s)
        # as extra files: (name, source, blocked, {parent: source}).
        decl_cases = [
            # The live hole: a production module whose name has a `test`
            # segment (src/mcp/dispatch_test_hook.rs, no cfg on its `mod`).
            ('mcp/dispatch_test_hook.rs', body, True,
             {'mcp/mod.rs': '#[doc(hidden)]\npub mod dispatch_test_hook;\n'}),
            # Undeclared / unresolvable => production (fail closed).
            ('peer_tests.rs', body, True, {}),
            # A `mod` inside an inline module lives at a different path.
            ('peer_tests.rs', body, True,
             {'lib.rs': '#[cfg(test)]\nmod t {\n    mod peer_tests;\n}\n'}),
            # cfg(any(test, feature)) is production when the feature is on.
            ('identity/test_key_dir.rs', body, True,
             {'identity/mod.rs': '#[cfg(any(test, feature = "test-support"))]\npub mod test_key_dir;\n'}),
            # cfg(test) declarations in every recognised form => test-only.
            ('peer_tests.rs', body, False, {'lib.rs': '#[cfg(test)]\nmod peer_tests;\n'}),
            ('test_peer.rs', body, False, {'main.rs': '#[cfg(test)] mod test_peer;\n'}),
            ('peer_test_helpers.rs', body, False,
             {'lib.rs': '#[cfg(all(test, feature = "sal"))]\npub(crate) mod peer_test_helpers;\n'}),
            ('mcp/peer_tests.rs', body, False, {'mcp.rs': '#[cfg(test)]\nmod peer_tests;\n'}),
            ('handlers/tests.rs', body, False,
             {'handlers/mod.rs': '#[cfg(test)]\n#[path = "tests.rs"]\nmod tests;\n'}),
            ('store/inbox_tests.rs', body, False,
             {'store/pg.rs': '#[cfg(test)]\nmod t {\n    include!("inbox_tests.rs");\n}\n'}),
            # One production declaration anywhere => production.
            ('handlers/tests.rs', body, True,
             {'handlers/mod.rs': '#[path = "tests.rs"]\nmod tests;\n'}),
            ('store/inbox_tests.rs', body, True,
             {'store/pg.rs': 'mod t {\n    include!("inbox_tests.rs");\n}\n'}),
            ('peer_tests.rs', body, True,
             {'lib.rs': '#[cfg(test)]\nmod peer_tests;\n#[path = "peer_tests.rs"]\npub mod shadow;\n'}),
            ('peer_tests.rs', body, True,
             {'lib.rs': '#[cfg(test)]\nmod peer_tests;\n', 'main.rs': 'mod peer_tests;\n'}),
            # Test-only only when the WHOLE chain is: a cfg(test) parent
            # hides its child, a production parent does not.
            ('a_tests/b_tests.rs', body, False,
             {'a_tests.rs': 'mod b_tests;\n', 'lib.rs': '#[cfg(test)]\nmod a_tests;\n'}),
            ('a_tests/b_tests.rs', body, True,
             {'a_tests.rs': 'mod b_tests;\n', 'lib.rs': 'mod a_tests;\n'}),
            # Conservative: a parent is only re-examined when it is itself
            # test-NAMED, so a cfg(test) parent with a plain name keeps its
            # children visible (over-inclusion, never a skip).
            ('a/b_tests.rs', body, True,
             {'a.rs': 'mod b_tests;\n', 'lib.rs': '#[cfg(test)]\nmod a;\n'}),
        ]
        cases = [(name, source, blocked, {}) for name, source, blocked in cases] + decl_cases
        if gate == 'qc-codegraph-precheck.sh':
            marker = 'GOVERNANCE_INTERNAL'
            site = '            let ctx = CallerContext::for_admin(crate::identity::sentinels::GOVERNANCE_INTERNAL);'
            # #3638 exclusion must not hide any neighboring or new bypass.
            cases = [(name, source, blocked, 'production-probe-3623', extra)
                     for name, source, blocked, extra in cases]
            cases += [
                ('store/postgres.rs', '\n' * 31499 + site, False, marker, {}),
                ('store/postgres.rs', '\n' * 31500 + site, True, marker, {}),
                ('store/postgres.rs', '\n' * 31499 + site + '\n' + site, True, marker, {}),
                ('store/other.rs', '\n' * 31499 + site, True, marker, {}),
                ('store/postgres.rs', '\n' * 31499 + site.replace('let ctx', 'let other'), True, marker, {}),
            ]
        else:
            cases = [(name, source, blocked, marker, extra) for name, source, blocked, extra in cases]
        for i, (name, source, blocked, marker, extra) in enumerate(cases):
            written = []
            for rel, text in [(name, source), *extra.items()]:
                path = tree / 'src' / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text + '\n')
                written.append(path)
            run = subprocess.run(['bash', str(tree / 'scripts' / gate)], capture_output=True, text=True)
            for path in written:
                path.unlink()
            output = run.stdout + run.stderr
            ok = (run.returncode == 1 and marker in output) if blocked else run.returncode == 0
            count += 1
            failures += not ok
            print(f'{"PASS" if ok else "FAIL"} #3623 {gate} case {i + 1}: {name}{" +" + ",".join(extra) if extra else ""} expected {"blocked" if blocked else "clean"}', flush=True)
            if not ok:
                print(output)
print(f'#3623: {count} tests, {failures} failures')
sys.exit(bool(failures))
