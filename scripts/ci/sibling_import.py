"""Load an intentional sibling when -I/-P removes the script directory.

Resolve only the supplied caller's adjacent file, never add a search directory.
A failed import removes its partial registration so a later import can retry.
"""
import importlib.util
from pathlib import Path
import sys


def load_sibling(name, caller_file):
    """Load a path-bound module, retaining dataclass-compatible registration."""
    path = Path(caller_file).resolve().with_name(name + ".py")
    existing = sys.modules.get(name)
    if existing is not None:
        actual = Path(getattr(existing, "__file__", "")).resolve()
        if actual != path:
            raise ImportError(f"sibling {name!r} already loaded from {actual}; expected {path}")
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"no loader for sibling {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(name) is module:
            sys.modules.pop(name, None)
        raise
    return module
