#!/usr/bin/env python3
"""Issue #3623: exercise each real gate in an isolated source tree."""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile



def exemption_constants(gate_path):
    """Read the exemption constants from the gate file itself (#5884)."""
    text = gate_path.read_text()
    out = {}
    for key in ('C8_EXEMPT_FILE', 'C8_EXEMPT_FN', 'C8_EXEMPT_LINE'):
        m = re.search(r"^" + key + r"='([^']*)'$", text, re.M)
        if not m:
            raise SystemExit(f'gate constant {key} not found')
        out[key] = m.group(1)
    return out


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
            # #5884: the exemption layout comes from the constants the gate
            # itself uses, never from a copied line number or line text.
            consts = exemption_constants(tree / 'scripts' / gate)
            gate_file, fn, site = consts['C8_EXEMPT_FILE'], consts['C8_EXEMPT_FN'], consts['C8_EXEMPT_LINE']
            pg = gate_file.split('/', 1)[1]  # fixtures live under the tree's src/
            # The shipped allowlist carries a file-wide postgres.rs entry that
            # would hide every case below; the exemption logic is tested alone.
            allow = tree / 'scripts' / 'qc-codegraph-allowlists' / 'for-admin-bypass.txt'
            allow.write_text(''.join(l for l in allow.read_text().splitlines(True)
                                     if l.strip() != f'{gate_file}:GOVERNANCE_INTERNAL'))
            def fnsrc(name, *lines, head='    async fn'):
                return f'impl Store {{\n{head} {name}(&self) {{\n' + '\n'.join(lines) + '\n    }\n}\n'
            real = fnsrc(fn, site)
            other = fnsrc('other_fn', site)
            multi = '        CallerContext::for_admin(\n            crate::identity::sentinels::GOVERNANCE_INTERNAL);'
            cmt = '    #[cfg(test)]\n    mod tests {\n        fn t() {\n' + site + '\n        }\n    }\n'
            cases = [(name, source, blocked, 'production-probe-3623')
                     for name, source, blocked in cases]
            cases += [
                (pg, real, False, marker),                                   # a: the intended site passes
                (pg, '\n' * 40 + real, False, marker),                       # f: shifted by inserted lines
                (pg, '\n' * 31500 + real, False, marker),                    # f: shifted far past the old pin
                (pg, real + other, True, (marker, gate_file, 'found 2')),                            # b: same line in a second fn
                (pg, real + fnsrc('other_fn', multi), True, marker),         # b: second site, other shape
                (pg, other, True, marker),                                   # c: moved to another fn
                (pg, fnsrc(fn + '_renamed', site), True, (marker, gate_file, 'inside fn ' + fn + '_renamed')),            # d: anchor renamed
                (pg, fnsrc(fn, site, site), True, (marker, gate_file, 'found 2')),                   # e: duplicated in the same fn
                ('store/other.rs', real, True, marker),                      # other file
                # same line number and text as the exempt site, in another file, next to the real one
                (pg, {pg: real, 'store/other.rs': fnsrc('x', site)}, True, marker),
                (pg, fnsrc(fn, site.replace('let ctx', 'let other')), True, marker),
                # neighbour probes
                (pg, fnsrc(fn, site + ' '), True, (marker, gate_file, 'found 0; the')),                   # trailing space
                (pg, fnsrc(fn, site + ' // note'), True, (marker, gate_file, 'found 0; the')),            # trailing comment
                (pg, fnsrc(fn, site.replace('    ', '\t', 1)), True, marker),  # tab indent
                (pg, fnsrc(fn, site.replace('for_admin(', 'for_admin(\n')), True, marker),  # break in call
                (pg, fnsrc(fn, '    // ' + site.strip(), site), False, marker),  # comment copy plus real
                (pg, fnsrc(fn, '    /// ' + site.strip(), site), False, marker),
                (pg, fnsrc(fn, '        let s = "' + site.strip() + '";', site), True, marker),  # string copy
                (pg, real + cmt, False, marker),                             # cfg(test) copy plus real
                (pg, cmt, True, marker),                                     # cfg(test) copy only
                (pg, 'fn nothing() {}\n', True, (marker, gate_file, 'found 0; the')),                     # zero matches in the file
                (pg, fnsrc(fn, site + '\r'), True, (marker, gate_file, 'found 0; the')),                  # CRLF
                (pg, fnsrc(fn, '        let f = || {', site, '        };'), False, marker),  # closure
                (pg, fnsrc(fn, site, head='    pub(crate) async fn'), False, marker),
                (pg, fnsrc(fn + '_v2', site), True, marker),                 # anchor name prefix
                (pg, fnsrc(fn, '        fn helper() {}', site), True, marker),  # nested fn encloses the site
                (pg, real + 'fn after() {}\n', False, marker),
                ('store/postgres_x.rs', real, True, marker),                 # sibling file name
                (pg, '// \u00e9\u00e8 caf\u00e9\n' + real, False, marker),   # unicode above
                (pg, fnsrc(fn, site, '        let _ = 1;', site), True, marker),  # duplicate, split
            ]
        else:
            cases = [(name, source, blocked, marker) for name, source, blocked in cases]
        for i, (name, source, blocked, marker) in enumerate(cases):
            files = source if isinstance(source, dict) else {name: source}
            paths = []
            for fname, text in files.items():
                path = tree / 'src' / fname
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text + '\n')
                paths.append(path)
            run = subprocess.run(['bash', str(tree / 'scripts' / gate)], capture_output=True, text=True)
            for path in paths:
                path.unlink()
            output = run.stdout + run.stderr
            needles = marker if isinstance(marker, tuple) else (marker,)
            ok = (run.returncode == 1 and all(n in output for n in needles)) if blocked else run.returncode == 0
            count += 1
            failures += not ok
            print(f'{"PASS" if ok else "FAIL"} #3623 {gate} case {i + 1}: {name} expected {"blocked" if blocked else "clean"}', flush=True)
            if not ok:
                print(output)
if 'qc-codegraph-precheck.sh' in gates:
    # #5884: the constants must name the REAL site. Prove it against the real
    # source file: exactly one line, inside the anchor function, and the gate
    # accepts it as the exemption (no exemption diagnostic).
    consts = exemption_constants(root / 'scripts' / 'qc-codegraph-precheck.sh')
    real_text = (root / consts['C8_EXEMPT_FILE']).read_text().splitlines()
    hits = [i for i, l in enumerate(real_text) if l == consts['C8_EXEMPT_LINE']]
    anchors = [i for i, l in enumerate(real_text) if re.match(r'\s*(pub(\([^)]*\))?\s+)?(async\s+)?fn\s+' + consts['C8_EXEMPT_FN'] + r'\b', l)]
    ok = len(hits) == 1 and len(anchors) == 1 and anchors[0] < hits[0]
    with tempfile.TemporaryDirectory(prefix='gate-3623-') as tmp:
        tree = pathlib.Path(tmp)
        shutil.copytree(root / 'scripts', tree / 'scripts')
        allow = tree / 'scripts' / 'qc-codegraph-allowlists' / 'for-admin-bypass.txt'
        allow.write_text(''.join(l for l in allow.read_text().splitlines(True)
                                 if l.strip() != consts['C8_EXEMPT_FILE'] + ':GOVERNANCE_INTERNAL'))
        dest = tree / consts['C8_EXEMPT_FILE']
        dest.parent.mkdir(parents=True)
        shutil.copyfile(root / consts['C8_EXEMPT_FILE'], dest)
        run = subprocess.run(['bash', str(tree / 'scripts' / 'qc-codegraph-precheck.sh')], capture_output=True, text=True)
        ok = ok and 'needs exactly 1' not in run.stdout + run.stderr
    count += 1
    failures += not ok
    print(f'{"PASS" if ok else "FAIL"} #3623 qc-codegraph-precheck.sh real {consts["C8_EXEMPT_FILE"]}: one exempt site in fn {consts["C8_EXEMPT_FN"]}', flush=True)
print(f'#3623: {count} tests, {failures} failures')
sys.exit(bool(failures))
