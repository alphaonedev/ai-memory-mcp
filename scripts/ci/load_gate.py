#!/usr/bin/env python3
"""Per-runner host load gate for the self-hosted CI legs (#6795).

Waits (bounded) while the 1-minute load average exceeds ``ratio x cores``, then
proceeds. It NEVER fails on load alone: after ``--max-wait-secs`` it prints a
``::warning::`` and exits 0, so a busy host delays a leg but never turns it red.
Exit 2 is reserved for bad arguments. Exit 3: the shared workflow_annotation.py
next to this file cannot be loaded (a broken checkout, one ``::error`` line, #9365).

Usage: python3 scripts/ci/load_gate.py --label "<os>/<tier>" [--max-ratio 1.5]
       [--max-wait-secs 1200] [--poll-secs 30]

Python 3.9+, standard library only.
"""
import argparse
import os
import sys
import time


def _load_workflow_annotation():
    """The shared module at WA_RELATIVE_PATH from this file's real directory, by path only, never through
    sys.path; every name in WA_REQUIRED must be a callable of it (#9365, one shape in every script)."""
    import importlib.util
    import os
    path = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), WA_RELATIVE_PATH))
    loaded = sys.modules.get("workflow_annotation")
    if loaded is not None and os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
        module = loaded
    else:
        spec = importlib.util.spec_from_file_location("workflow_annotation", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # absent, unreadable or broken: it raises here, the try below catches it
    missing = [name for name in WA_REQUIRED if not callable(getattr(module, name, None))]
    if missing:
        raise AttributeError("workflow_annotation.py lacks " + ", ".join(missing))
    if loaded is None:
        sys.modules["workflow_annotation"] = module
    return module


EXIT_LOAD_REFUSED = 3  # the shared module cannot be loaded (0 = proceed, 2 = bad arguments)

# The one shared-module load shape of scripts/ (#9365, ruling bcd0a15c; LoaderShape pins it).
WA_PROG = "load_gate"
WA_RELATIVE_PATH = "workflow_annotation.py"
WA_REQUIRED = ("annotation", "log_line")
WA_EXIT_LOAD_REFUSED = EXIT_LOAD_REFUSED  # the gate's own refusal code, unchanged
WA_ERROR_TO_STDERR = False

try:
    wa = _load_workflow_annotation()
except (Exception, SystemExit) as exc:  # any failed load: one fixed line built without the module, then exit
    wa_cause = type(exc).__name__
    print("%s: refused: shared module workflow_annotation.py next to the script cannot be loaded (%s)"
          % (WA_PROG, wa_cause if wa_cause.isidentifier() else "BaseException"), file=sys.stderr, flush=True)
    print("::error title=load_gate refused::load_gate: refused: shared module workflow_annotation.py"
          " next to the script cannot be loaded",
          file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
    sys.exit(WA_EXIT_LOAD_REFUSED)

TAG = '[#6795 load gate]'


def should_wait(load, cores, ratio):
    """True when the host is busier than ``ratio x cores``. Unknown cores: never wait."""
    if not cores or cores <= 0:
        return False
    return load > ratio * cores


def format_notice(label, load, cores, ratio, waited):
    return wa.annotation("notice", "%s '%s': load=%.2f cores=%d ratio=%s waited=%ds" % (
        TAG, label, load, cores, ratio, waited))


def _plain(label, load, cores, ratio, waited):
    """Intermediate poll line: plain log text, not an annotation (GitHub caps annotations per step)."""
    return wa.log_line("%s '%s': waiting, load=%.2f cores=%d ratio=%s waited=%ds" % (
        TAG, label, load, cores, ratio, waited))


def run(label, max_ratio, max_wait_secs, poll_secs, cores, load_fn, sleep_fn):
    """Poll until the load is acceptable or the wait budget is spent. Always returns 0."""
    waited = 0
    try:
        load = load_fn()
    except (OSError, AttributeError) as exc:
        print(wa.annotation("warning", "%s '%s': cannot read the load average (%s); proceeding without the gate"
                            % (TAG, label, exc)), flush=True)
        return 0
    print(format_notice(label, load, cores, max_ratio, waited), flush=True)
    while should_wait(load, cores, max_ratio):
        if waited >= max_wait_secs:
            print(wa.annotation("warning", "%s '%s': load=%.2f still above %s x %d cores after %ds; "
                                "proceeding anyway (the gate never fails on load alone)"
                                % (TAG, label, load, max_ratio, cores, waited)), flush=True)
            break
        step = min(poll_secs, max_wait_secs - waited)
        sleep_fn(step)
        waited += step
        try:
            load = load_fn()
        except (OSError, AttributeError) as exc:
            print(wa.annotation("warning", "%s '%s': load average became unreadable (%s); proceeding"
                                % (TAG, label, exc)), flush=True)
            return 0
        if should_wait(load, cores, max_ratio):
            print(_plain(label, load, cores, max_ratio, waited), flush=True)
    print(format_notice(label, load, cores, max_ratio, waited), flush=True)
    return 0


def _positive_float(text):
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError('must be > 0')
    return value


def _positive_int(text):
    value = int(text)
    if value <= 0:
        raise argparse.ArgumentTypeError('must be > 0')
    return value


def _non_negative_int(text):
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError('must be >= 0')
    return value


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--max-ratio', type=_positive_float, default=1.5)
    p.add_argument('--max-wait-secs', type=_non_negative_int, default=1200)
    p.add_argument('--poll-secs', type=_positive_int, default=30)
    p.add_argument('--label', default='unlabelled')
    args = p.parse_args(argv)  # argparse exits 2 on bad arguments
    return run(args.label, args.max_ratio, args.max_wait_secs, args.poll_secs,
               os.cpu_count(), lambda: os.getloadavg()[0], time.sleep)


if __name__ == '__main__':
    sys.exit(main())
