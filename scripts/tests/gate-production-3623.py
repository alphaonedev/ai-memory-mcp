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
            # #3638 exclusion must not hide any neighboring or new bypass.
            cases = [(name, source, blocked, 'production-probe-3623')
                     for name, source, blocked in cases]
            cases += [
                ('store/postgres.rs', '\n' * 31499 + site, False, marker),
                ('store/postgres.rs', '\n' * 31500 + site, True, marker),
                ('store/postgres.rs', '\n' * 31499 + site + '\n' + site, True, marker),
                ('store/other.rs', '\n' * 31499 + site, True, marker),
                ('store/postgres.rs', '\n' * 31499 + site.replace('let ctx', 'let other'), True, marker),
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
