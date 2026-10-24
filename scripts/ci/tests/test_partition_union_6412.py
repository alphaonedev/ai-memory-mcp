#!/usr/bin/env python3
"""Union invariant for the lib Postgres gate (#6412 r3, #6425; 5-agent vote (4d3ea1c5)).

``lib_pg_sites`` is the union of the 674a893c8 bare-name matcher and the path/alias/macro
resolver. The resolver may add sites; it may never remove one the bare-name matcher found. The
oracle below is that matcher, verbatim, over the same lib units. The only base hits it may
lose are lexical false positives: a name inside a string/char literal and a ``.name(`` method
call of a free fn, single dot only (comments are already blanked by the ``code`` view).

Run: python3 -m unittest discover -s scripts/ci/tests
"""
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import partition_test_binaries as pt  # noqa: E402
import test_partition_test_binaries as TB  # noqa: E402

REPO = TB.REPO
SCRATCH = TB.SCRATCH
fx = TB.fx


def reference_sites_674a(src_root):
    """{(path, loc): lexical} of the 674a893c8 ``lib_pg_sites``: bare-name matcher over the ``code`` view.

    ``lexical`` marks a call hit that sits inside a string/char literal or after a ``.``.
    """
    units = pt.lib_units(src_root)
    consts = set()
    for rf, _ in units:
        consts.update(m.group(1) for m in pt.PG_CONST_RE.finditer(rf.code))
    const_re = re.compile(r'\b(%s)\b' % '|'.join(map(re.escape, sorted(consts)))) if consts else None
    out, helpers = {}, {}

    def site_path(modp, ctx):
        parts = [modp] if modp else []
        test_fn = None
        for kind, name, is_test in ctx:
            if kind == 'mod' and test_fn is None:
                parts.append(name)
            elif kind == 'fn' and is_test and test_fn is None:
                test_fn = name
        if test_fn:
            parts.append(test_fn)
        return '::'.join(parts), test_fn

    for rf, modp in units:
        pos = [m.start() for m in pt.PG_TOKEN_RE.finditer(rf.code)]
        if const_re is not None:
            pos += [m.start() for m in const_re.finditer(rf.code)]
        for at, ctx in zip(pos, rf.contexts(pos)):
            path, test_fn = site_path(modp, ctx)
            if test_fn is None:
                fns = [name for kind, name, _ in ctx if kind == 'fn']
                if fns:
                    helpers.setdefault(fns[-1], set()).add(path)
            out[(path, '%s:%d' % (rf.path, rf.code.count('\n', 0, at) + 1))] = False
    if helpers:
        call_re = re.compile(r'\b(%s)\s*\(' % '|'.join(map(re.escape, sorted(helpers))))
        for rf, modp in units:
            calls = [m for m in call_re.finditer(rf.code)
                     if not pt.FN_BEFORE_RE.search(rf.code[max(0, m.start() - 16):m.start()])]
            for m, ctx in zip(calls, rf.contexts([m.start() for m in calls])):
                path, _ = site_path(modp, ctx)
                if path not in helpers[m.group(1)]:
                    lexical = (rf.shape[m.start():m.end()] != rf.code[m.start():m.end()]
                               or pt.after_method_dot(rf.code[max(0, m.start() - 256):m.start()]))
                    out[(path, '%s:%d (calls %s)' % (rf.path, rf.code.count('\n', 0, m.start()) + 1, m.group(1)))] = lexical
    return out


def lost_base_sites(src_root):
    """Non-lexical sites the 674a893c8 matcher reports that ``lib_pg_sites`` does not."""
    ref = reference_sites_674a(src_root)
    tip = set(pt.lib_pg_sites(src_root))
    return sorted(s for s, lexical in ref.items() if not lexical and s not in tip)


class SupersetGate:
    """Mixin: after every ``gate(...)`` of a r1/r2 fixture class, the 674a893c8 sites are all still sites."""

    def gate(self, *args, **kwargs):
        result = super().gate(*args, **kwargs)
        self.assertEqual(lost_base_sites(SCRATCH / 'src'), [], 'a base-matcher site was dropped (fail open)')
        return result


class LibCallerResolution6412Superset(SupersetGate, TB.LibCallerResolution6412):
    """Every fixture of the r1 class, re-run with the superset check."""


class LibCallerTransitive6412Superset(SupersetGate, TB.LibCallerTransitive6412):
    """Every fixture of the r2 class, re-run with the superset check."""


class LibMacroCaller6425Superset(SupersetGate, TB.LibMacroCaller6425):
    """Every fixture of the #6425 class, re-run with the superset check."""

    gate = SupersetGate.gate




# adv2.py (review r2): the cases the 32bae94b1 resolver failed or passed, verbatim.
URL = 'std::env::var("AI_MEMORY_TEST_POSTGRES_URL").unwrap()'
SUP = 'pub(crate) fn live_pg_url() -> String { %s }\n' % URL
DEEP = 'pub mod sup { pub fn dpg() -> String { %s } }\n' % URL
OTHER = 'pub fn live_pg_url() -> u8 { 0 }\npub fn helper() {}\n'
def T(body, pre=''):
    return '#[cfg(test)]\nmod tests {\n    %s\n    #[test]\n    fn t() { %s }\n}\n' % (pre, body)
P = ['support']
PD = ['support', 'deep::sup']
CASES = [
  ('N1 3-hop re-export chain (plain,glob,plain)', {'a.rs': T('let _ = live_pg_url();', 'use crate::re1::live_pg_url;'),
     're1.rs': 'pub use crate::re2::live_pg_url;\n', 're2.rs': 'pub use crate::re3::*;\n', 're3.rs': 'pub use crate::support::live_pg_url;\n'}, P, ['a::tests::t']),
  ('N2 3-hop alias-of-alias chain', {'a.rs': T('let _ = c();', 'use crate::re1::c;'),
     're1.rs': 'pub use crate::re2::b as c;\n', 're2.rs': 'pub use crate::re3::a as b;\n', 're3.rs': 'pub use crate::support::live_pg_url as a;\n'}, P, ['a::tests::t']),
  ('N2b 4-hop via mod tests use super::* at the end', {'a.rs': 'use crate::re1::c;\n' + T('let _ = c();', 'use super::*;'),
     're1.rs': 'pub use crate::re2::*;\n', 're2.rs': 'pub use crate::re3::b as c;\n', 're3.rs': 'pub use crate::support::live_pg_url as b;\n'}, P, ['a::tests::t']),
  ('N3 pub use self::x::* + inline mod x same file', {'a.rs': T('let _ = live_pg_url();', 'use crate::re::live_pg_url;'),
     're.rs': 'pub use self::x::*;\nmod x { pub use crate::support::live_pg_url; }\n'}, P, ['a::tests::t']),
  ('N3b pub use self::x::* + file mod x', {'a.rs': T('let _ = live_pg_url();', 'use crate::re::*;'),
     're.rs': 'pub use self::x::*;\nmod x;\n', 're/x.rs': 'pub use crate::support::*;\n'}, P, ['a::tests::t']),
  ('N4 group use crate::{support::*, other::helper as h}', {'a.rs': T('h(); let _ = live_pg_url();', 'use crate::{support::*, other::helper as h};'), 'other.rs': OTHER}, P, ['a::tests::t']),
  ('N4b group use crate::{other::*, support::live_pg_url as h}', {'a.rs': T('let _ = h();', 'use crate::{other::*, support::live_pg_url as h};'), 'other.rs': OTHER}, P, ['a::tests::t']),
  ('N5 re-export cycle, helper on one side', {'a.rs': T('let _ = live_pg_url();', 'use crate::re2::*;'),
     're.rs': 'pub use crate::re2::*;\npub use crate::support::live_pg_url;\n', 're2.rs': 'pub use crate::re::*;\n'}, P, ['a::tests::t']),
  ('N5b re-export cycle, helper behind second glob', {'a.rs': T('let _ = live_pg_url();', 'use crate::re::*;'),
     're.rs': 'pub use crate::re2::*;\n', 're2.rs': 'pub use crate::re::*;\npub use crate::support::*;\n'}, P, ['a::tests::t']),
  ('N5c pure re-export cycle (must terminate)', {'a.rs': T('let _ = live_pg_url();', 'use crate::re::*;'),
     're.rs': 'pub use crate::re2::*;\n', 're2.rs': 'pub use crate::re::*;\n'}, P, None),
  ('N6 #[path] module at root', {'lib.rs': 'mod support;\n#[path = "weird/pgx.rs"]\nmod a;\n',
     'weird/pgx.rs': 'use crate::support::live_pg_url;\n' + T('let _ = live_pg_url();', 'use super::*;')}, P, ['a::tests::t']),
  ('N6b #[path] child mod inside a.rs', {'a.rs': '#[path = "zz.rs"]\nmod b;\n', 'zz.rs': 'use crate::support::*;\n' + T('let _ = live_pg_url();', 'use super::*;')}, P, ['a::b::tests::t']),
  ('N7 include! of the tests module', {'a.rs': 'use crate::support::live_pg_url;\ninclude!("a_tests.rs");\n', 'a_tests.rs': T('let _ = live_pg_url();', 'use super::*;')}, P, ['a::tests::t']),
  ('N7b include! of the import', {'a.rs': 'include!("a_imp.rs");\n' + T('let _ = live_pg_url();', 'use super::*;'), 'a_imp.rs': 'use crate::support::live_pg_url;\n'}, P, ['a::tests::t']),
  ('N8 macro_rules inside a test fn', {'a.rs': T('macro_rules! m { () => { live_pg_url() } } let _ = m!();', 'use crate::support::*;')}, P, ['a::tests::t']),
  ('N8b macro body bare name, resolved at invoking module', {'a.rs': T('let _ = crate::mm!();', 'use crate::support::live_pg_url;'),
     'm.rs': '#[macro_export]\nmacro_rules! mm { () => { live_pg_url() } }\n'}, P, ['a::tests::t']),
  ('N8c macro chain (outer -> inner -> helper), paren delim', {'a.rs': T('let _ = outer!();', 'use crate::support::*;'),
     'm.rs': '#[macro_export]\nmacro_rules! inner ( () => { $crate::support::live_pg_url() } );\n#[macro_export]\nmacro_rules! outer { () => { $crate::inner!() } }\n'}, P, ['a::tests::t']),
  ('N9 associated fn Pg::url() (impl static)', {'a.rs': 'pub struct Pg;\nimpl Pg { pub fn url() -> String { %s } }\n' % URL, 'b.rs': T('let _ = crate::a::Pg::url();')}, ['a'], ['b::tests::t']),
  ('N9b trait static <X as P>::url() default method', {'a.rs': 'pub trait P { fn url() -> String { %s } }\npub struct X;\nimpl P for X {}\n' % URL,
     'b.rs': T('let _ = <crate::a::X as crate::a::P>::url();')}, ['a'], ['b::tests::t']),
  ('N9c Self::url() inside impl test helper', {'a.rs': 'pub struct Pg;\nimpl Pg { fn url() -> String { %s } pub fn go() -> String { Self::url() } }\n' % URL, 'b.rs': T('let _ = crate::a::Pg::go();')}, ['a'], ['b::tests::t']),
  ('N10 external-crate glob shadows nothing', {'a.rs': 'use crate::support::live_pg_url;\n' + T('let _ = live_pg_url();', 'use super::*; use std::collections::*;')}, P, ['a::tests::t']),
  ('N11 glob-sourced qualifier (nested module via use super::*)', {'a.rs': 'use crate::deep::sup;\n' + T('let _ = sup::dpg();', 'use super::*;'), 'deep.rs': DEEP}, PD, ['a::tests::t']),
  ('N11b explicit qualifier import (control)', {'a.rs': T('let _ = sup::dpg();', 'use crate::deep::sup;'), 'deep.rs': DEEP}, PD, ['a::tests::t']),
  ('N11c module alias via use super::*', {'a.rs': 'use crate::support as s;\n' + T('let _ = s::live_pg_url();', 'use super::*;')}, P, ['a::tests::t']),
  ('N11d glob-imported module from deep glob', {'a.rs': T('let _ = sup::dpg();', 'use crate::deep::*;'), 'deep.rs': DEEP}, PD, ['a::tests::t']),
  ('N12 fn-local use in a non-test fn hides the module glob', {'a.rs': 'use crate::support::*;\nfn other() { use crate::other::live_pg_url; let _ = live_pg_url(); }\n' + T('let _ = live_pg_url();', 'use super::*;'), 'other.rs': OTHER}, P, ['a::tests::t']),
  ('N12b fn-local use in sibling test fn hides tests glob', {'a.rs': '#[cfg(test)]\nmod tests {\n use crate::support::*;\n #[test] fn t1() { use crate::other::live_pg_url; let _ = live_pg_url(); }\n #[test] fn t() { let _ = live_pg_url(); }\n}\n', 'other.rs': OTHER}, P, ['a::tests::t']),
  ('N13 cfg(not(test)) stub fn + cfg(test) import', {'a.rs': '#[cfg(not(test))]\nfn live_pg_url() -> String { String::new() }\n#[cfg(test)]\nuse crate::support::live_pg_url;\n' + T('let _ = live_pg_url();', 'use super::*;')}, P, ['a::tests::t']),
  ('N13b feature-gated stub + feature-gated aliased import', {'a.rs': '#[cfg(not(feature = "sal-postgres"))]\nfn pg_url() -> Option<String> { None }\n#[cfg(feature = "sal-postgres")]\nuse crate::support::live_pg_url as pg_url;\n' + T('let _ = pg_url();', 'use super::*;')}, P, ['a::tests::t']),
  ('N14 type-namespace mod of same name does not shadow fn', {'a.rs': 'use crate::support::*;\n#[allow(non_snake_case)] mod live_pg_url {}\n' + T('let _ = live_pg_url();', 'use super::*;')}, P, ['a::tests::t']),
  ('N15 unresolvable glob (macro-made module) fails closed', {'a.rs': T('let _ = live_pg_url();', 'use crate::gen::*;')}, P, ['a::tests::t']),
  ('N15b unresolvable explicit import fails closed', {'a.rs': T('let _ = live_pg_url();', 'use crate::gen::live_pg_url;')}, P, ['a::tests::t']),
  ('N16 second-order helper in another module', {'b.rs': 'pub fn h2() -> String { crate::support::live_pg_url() }\n', 'a.rs': T('let _ = crate::b::h2();')}, P, ['a::tests::t']),
  ('N17 helper through fn-pointer const', {'a.rs': 'const F: fn() -> String = crate::support::live_pg_url;\n' + T('let _ = F();', 'use super::*;')}, P, ['a']),
]

# adversarial.py (review r1): the original 20 probes; expected = test paths a true caller reaches.
HELPER = LIVE = 'pub(crate) fn live_pg_url() -> String { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").unwrap() }\n'
CASES_R1 = [
  # name, files(dict), expected uncovered with prefixes ['support'] (true callers)
  ('C1 use super::* in mod tests, parent imports helper', {'a.rs': 'use crate::support::live_pg_url;\n' + T('let _ = live_pg_url();', 'use super::*;')}, ['a::tests::t']),
  ('C2 use super::* in mod tests, parent glob-imports support', {'a.rs': 'use crate::support::*;\n' + T('let _ = live_pg_url();', 'use super::*;')}, ['a::tests::t']),
  ('C3 use super::* , parent aliases helper', {'a.rs': 'use crate::support::live_pg_url as u;\n' + T('let _ = u();', 'use super::*;')}, ['a::tests::t']),
  ('C4 helper in parent module, mod tests use super::*', {'a.rs': 'fn h() -> String { crate::support::live_pg_url() }\n' + T('let _ = h();', 'use super::*;')}, ['a']),
  ('R1 pub use re-export then plain use', {'a.rs': T('let _ = live_pg_url();', 'use crate::re::live_pg_url;'), 're.rs': 'pub use crate::support::live_pg_url;\n'}, ['a::tests::t']),
  ('R2 pub use re-export then glob use', {'a.rs': T('let _ = live_pg_url();', 'use crate::re::*;'), 're.rs': 'pub use crate::support::live_pg_url;\n'}, ['a::tests::t']),
  ('R3 pub use glob re-export then plain use', {'a.rs': T('let _ = live_pg_url();', 'use crate::re::live_pg_url;'), 're.rs': 'pub use crate::support::*;\n'}, ['a::tests::t']),
  ('R4 qualified through re-export', {'a.rs': T('let _ = crate::re::live_pg_url();'), 're.rs': 'pub use crate::support::live_pg_url;\n'}, ['a::tests::t']),
  ('R5 pub use re-export with rename', {'a.rs': T('let _ = crate::re::pg();'), 're.rs': 'pub use crate::support::live_pg_url as pg;\n'}, ['a::tests::t']),
  ('S1 local fn shadows glob (not a caller; fail-closed ok)', {'a.rs': 'use crate::support::*;\nfn live_pg_url() -> u8 { 0 }\n' + T('let _ = super::live_pg_url();')}, []),
  ('P1 path expr no use', {'a.rs': T('let _ = crate::support::live_pg_url();')}, ['a::tests::t']),
  ('P2 super::super path', {'a.rs': T('let _ = super::super::support::live_pg_url();')}, ['a::tests::t']),
  ('P3 fn-local use in test', {'a.rs': T('use crate::support::live_pg_url as u; let _ = u();')}, ['a::tests::t']),
  ('P4 nested group', {'a.rs': 'use crate::{support::{self, live_pg_url}};\n' + T('let _ = super::support::live_pg_url(); let _ = super::live_pg_url();')}, ['a::tests::t']),
  ('M1 macro_rules in same module', {'a.rs': 'macro_rules! m { () => { crate::support::live_pg_url() } }\n' + T('let _ = m!();')}, ['a::tests::t']),
  ('M2 macro_export in other module', {'a.rs': T('let _ = crate::mm!();'), 're.rs': '#[macro_export]\nmacro_rules! mm { () => { $crate::support::live_pg_url() } }\n'}, ['a::tests::t']),
  ('K1 child file mod with use super::live_pg_url', {'a.rs': 'use crate::support::live_pg_url;\nmod b;\n', 'a/b.rs': T('let _ = live_pg_url();', 'use super::super::live_pg_url;')}, ['a::b::tests::t']),
  ('X1 ambiguous: two globs both export the name', {'a.rs': T('let _ = live_pg_url();', 'use crate::support::*; use crate::other::*;'), 'other.rs': 'pub fn x() {}\n'}, ['a::tests::t']),
  ('X2 helper name used as struct field init shorthand', {'a.rs': 'use crate::support::live_pg_url;\nstruct C { f: fn() -> String }\n' + T('let _ = C { f: super::live_pg_url };')}, ['a::tests::t']),
  ('X3 helper in mod tests of support, other mod tests imports via super chain', {'a.rs': T('let _ = crate::support::tests_support::pgurl();')}, ['a::tests::t']),
]

# Shapes no variant follows yet: a helper that only calls another helper (#6441). The superset
# invariant still runs on them; the expectation does not.
OUT_OF_SCOPE = {'N9c', 'N16'}


def write_case(files, support):
    """Lay a fixture crate out under SCRATCH/src and return its src root."""
    fx('src/support.rs', support)
    if 'lib.rs' not in files:
        tops = sorted({k.split('/')[0][:-3] if k.endswith('.rs') and '/' not in k else k.split('/')[0]
                       for k in files if not k.startswith(('a_', 'zz'))} | {'support'})
        fx('src/lib.rs', ''.join('mod %s;\n' % m for m in tops))
    for k, v in files.items():
        fx('src/' + k, v)
    return SCRATCH / 'src'


class CorpusUnion6412(TB.Base):
    """The 34 + 20 review probes: no base site is lost, and every expected true caller is reported."""

    def check(self, name, files, prefixes, expected, support):
        root = write_case(files, support)
        self.assertEqual(lost_base_sites(root), [], name + ': a base-matcher site was dropped (fail open)')
        if expected is not None and name.split()[0] not in OUT_OF_SCOPE:
            got = pt.uncovered_lib_pg_modules(root, prefixes)
            self.assertTrue(set(expected) <= set(got), '%s: expected %s, got %s' % (name, expected, got))

    def test_adv2_cases_6412(self):
        self.assertEqual(len(CASES), 34)
        for name, files, prefixes, expected in CASES:
            with self.subTest(name):
                self.setUp()
                self.check(name, files, prefixes, expected, SUP)

    def test_adversarial_r1_cases_6412(self):
        sup = LIVE + 'pub mod tests_support { pub fn pgurl() -> String { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").unwrap() } }\n'
        self.assertEqual(len(CASES_R1), 20)
        for name, files, expected in CASES_R1:
            with self.subTest(name):
                self.setUp()
                files = dict(files)
                mods = ['support', 'a'] + (['re'] if 're.rs' in files else []) + (['other'] if 'other.rs' in files else [])
                files['lib.rs'] = ''.join('mod %s;\n' % m for m in mods)
                self.check(name, files, ['support'], expected, sup)


# review r3 #6460: `..name(` (struct update, range) is a call site; only a single-dot receiver is a method call.
URL_CFG = 'std::env::var("AI_MEMORY_TEST_POSTGRES_URL").unwrap()'
SUP_6460 = SUP + 'pub(crate) fn pg_cfg() -> u8 { let _ = %s; 0 }\n' % URL_CFG + ''.join(
    'pub(crate) fn %s() -> u8 { let _ = %s; 0 }\n' % (n, URL_CFG)
    for n in ('failing_result', 'envelope', 'owned_by', 'fixture', 'succession_fixture'))
PRE_6460 = 'use crate::support::*; struct S { n: i32 }'
IDIOMS_6460 = (
    'let _a = S { n: 1,\n            ..failing_result()\n        };\n'
    '        let _b = S { n: 1, ..envelope("ns", "title", "body") };\n'
    '        let _c = S { n: 1, ..envelope("ns", "title", "body") };\n'
    '        let _d = S { n: 1, ..envelope("ns", "title", "body") };\n'
    '        let _e = S { n: 1, ..owned_by(owner) };\n'
    '        let _f = S { n: 1,\n            ..fixture("a1", Some("alice"))\n        };\n'
    '        let _g = S { n: 1, ..succession_fixture(&prev) };'
)
CASES_6460 = [
  ('D1 struct update ..pg_cfg()', {'a.rs': T('let _ = S { n: 1, ..pg_cfg() };', PRE_6460)}, ['a::tests::t']),
  ('D1b struct update, space after ..', {'a.rs': T('let _ = S { n: 1, .. pg_cfg() };', PRE_6460)}, ['a::tests::t']),
  ('D1c struct update, newline after ..', {'a.rs': T('let _ = S { n: 1,\n            ..\n            pg_cfg() };', PRE_6460)}, ['a::tests::t']),
  ('D2 range 0..live_pg_url().len()', {'a.rs': T('for _i in 0..live_pg_url().len() {}', PRE_6460)}, ['a::tests::t']),
  ('D2b inclusive range 0..=live_pg_url().len()', {'a.rs': T('for _i in 0..=live_pg_url().len() {}', PRE_6460)}, ['a::tests::t']),
  ('D3 qualified ..crate::support::pg_cfg()', {'a.rs': T('let _ = S { n: 1, ..crate::support::pg_cfg() };', PRE_6460)}, ['a::tests::t']),
  ('D5 the 7 real ..helper(..) idioms of src/', {'a.rs': T(IDIOMS_6460, PRE_6460)}, ['a::tests::t']),
  ('D4 control: x.live_pg_url() is a method call, not the free fn', {'a.rs': T('let x = 1u8; let _ = x.live_pg_url();', 'struct S { n: i32 }')}, []),
]


class DottedCalls6460(TB.Base):
    """`..helper()` is a call site in the tool AND in the oracle; `x.helper()` stays a method call."""

    def test_dotdot_calls_are_reported_6460(self):
        for name, files, expected in CASES_6460:
            with self.subTest(name):
                self.setUp()
                root = write_case(files, SUP_6460)
                self.assertEqual(lost_base_sites(root), [], name + ': a base-matcher site was dropped (fail open)')
                got = pt.uncovered_lib_pg_modules(root, ['support'])
                self.assertTrue(set(expected) <= set(got), '%s: expected %s, got %s' % (name, expected, got))
                if not expected:
                    self.assertEqual(list(got), [], name + ': a method call was reported')

    def test_oracle_does_not_exempt_dotdot_hits_6460(self):
        for name, files, expected in CASES_6460:
            if not expected:
                continue
            with self.subTest(name):
                self.setUp()
                ref = reference_sites_674a(write_case(files, SUP_6460))
                calls = {k: v for k, v in ref.items() if '(calls ' in k[1] and k[0] == 'a::tests::t'}
                self.assertTrue(calls, name + ': the oracle saw no call site')
                self.assertFalse(any(calls.values()), '%s: oracle exempted %s as lexical' % (name, calls))

    def test_oracle_exempts_a_single_dot_method_call_6460(self):
        files = dict(CASES_6460[-1][1])
        ref = reference_sites_674a(write_case(files, SUP_6460))
        calls = {k: v for k, v in ref.items() if '(calls ' in k[1]}
        self.assertTrue(calls and all(calls.values()), 'x.name() must stay a lexical (method call) hit: %s' % calls)


class RealTreeUnion6412(unittest.TestCase):
    def test_real_tree_sites_are_a_superset_of_the_bare_name_matcher_6412(self):
        self.assertEqual(lost_base_sites(REPO / 'src'), [])


class ResolverFailureIsRed6412(TB.Base):
    def test_resolver_exception_propagates_6412(self):
        write_case({'a.rs': TB.LibCallerTransitive6412.with_tests('let _ = live_pg_url();', 'use crate::support::live_pg_url;')}, SUP)
        original = pt.helper_callers

        def boom(*_a, **_k):
            raise RuntimeError('resolver bug')

        pt.helper_callers = boom
        try:
            with self.assertRaises(RuntimeError):
                pt.lib_pg_sites(SCRATCH / 'src')
        finally:
            pt.helper_callers = original


class LexicalExclusions6412(TB.Base):
    """The only exclusions: comments, string/char literals, `.name(` method calls, `.name` field access, the definition."""

    def sites(self, a_rs):
        write_case({'a.rs': a_rs}, SUP)
        return sorted({p for p, _w in pt.lib_pg_sites(SCRATCH / 'src') if p.startswith('a')})

    def test_comment_string_char_method_field_are_not_sites_6412(self):
        wt = TB.LibCallerTransitive6412.with_tests
        for body in ('// live_pg_url()', '/* /* live_pg_url() */ */', 'let _s = "live_pg_url()";',
                     'let _s = r#"live_pg_url()"#;', "let _c = 'x';", 'let _ = s.live_pg_url();',
                     'let _ = s.live_pg_url;', 'fn live_pg_url() {}'):
            with self.subTest(body):
                self.setUp()
                self.assertEqual(self.sites(wt(body)), [], body)

    def test_same_named_free_fn_is_an_over_match_by_design_6412(self):
        a = "fn live_pg_url() -> u8 { 0 }\n" + TB.LibCallerTransitive6412.with_tests('let _ = live_pg_url();')
        self.assertEqual(self.sites(a), ['a::tests::t'])


if __name__ == '__main__':
    unittest.main()
