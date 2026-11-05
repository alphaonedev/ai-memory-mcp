"""Independent path grammar: every future review finding adds a grammar axis.

Expected spans come from assembled pieces, never the scanner or its patterns.
Web-host absolute paths are public; named-tilde homes retain their anywhere rule.
Encoded separators and Windows backslashes remain declared unsupported forms.
"""

from dataclasses import dataclass
from itertools import product


@dataclass(frozen=True)
class Shape:
    """One generated document and its independently known private prefix spans."""

    label: str
    text: str
    spans: tuple[tuple[int, int], ...]

    def repaired(self) -> str:
        """Build the oracle directly from grammar-piece boundaries."""
        result = []
        offset = 0
        for start, end in self.spans:
            result.extend((self.text[offset:start], "<home>"))
            offset = end
        return "".join((*result, self.text[offset:]))


def shapes():
    """Cross roots, account classes, left contexts and right contexts."""
    roots = ("/home/", "/Users/", "/var/home/", "/mnt/c/Users/", "~",
             "home/", "Users/", "./home/", "../home/", "var/home/", "mnt/c/Users/")
    names = (("user", False), ("private_account", True))
    lefts = (
        ("start", "", ""), ("space", "at ", ""), ("colon", ":", ""),
        ("comma", ",", ""), ("bracket", "]", ""), ("paren", "(", ")"),
        ("quote", "'", "'"), ("include", "gcc -I", ""),
        ("library", "ld -L", ""), ("path", "PATH=", ""),
        ("scp", "scp host:", ""), ("docker", "docker -v ", ""),
        ("file", "file://", ""), ("file-upper", "FILE://", ""),
        ("file-single", "file:", ""), ("web", "https://host", ""),
        ("link", "[label](", ")"), ("image-alt", "![", "](asset)"),
        ("fence", "```bash\n", "\n```"), ("fence-upper", "```SH\n", "\n```"),
        ("url-comma", "https://example.test/a,", ""),
        ("url-bracket", "https://example.test/a]", ""),
        ("unicode", "λ ", ""), ("inline", "`", "`"),
    )
    # Round 6 Q2: only HTTP(S) routes are public; remote filesystem schemes are private.
    lefts += tuple(
        ("remote-" + spelling, spelling + "://host/", "")
        for scheme in ("ssh", "sftp", "rsync", "git+ssh", "scp", "smb", "nfs",
                       "git+http", "git+https")
        for spelling in (scheme, scheme.upper())
    )
    lefts += tuple(("web-" + scheme, scheme + "://host", "")
                   for scheme in ("http", "HTTP", "HTTPS"))
    rights = ("", "/", "/x", "/..", "/../y", ".", ",", ")", "]",
              "\\_tail", "\u200b", "\ufeff")
    for root, (name, private), (context, left, closing), right in product(
            roots, names, lefts, rights):
        web = context == "web" or context.startswith("web-")
        if web and not root.startswith("/"):
            left += "/"
        prefix = root + name
        tail = right
        # An escaped underscore extends the account, not the relative tail.
        if right == "\\_tail":
            prefix += right
            tail = ""
            private = True
        elif right in ("\u200b", "\ufeff"):
            prefix += right
            tail = ""
        # This production changes the resolved home account to private name 'y'.
        if right == "/../y" and root != "~":
            prefix += right
            tail = ""
            private = True
        public_web = web and root != "~"
        text = left + prefix + tail + closing + "\n"
        start = len(left)
        if context.startswith("remote-") and root != "~":
            # Plain filesystem tokens include the authority component after scheme://.
            start -= len("host/")
        spans = ((start, len(left) + len(prefix)),) if private and not public_web else ()
        yield Shape(f"{root}:{name}:{context}:{right!r}", text, spans)

    # Round 6 L1: URL-legal internal punctuation is public, including query/fragment text.
    for scheme, punctuation, root in product(
            ("http", "https", "HTTP", "HTTPS"), "+:@;=!$&*?#", roots):
        if root == "~":
            continue
        text = scheme + "://host/a" + punctuation + "b/" + root + "private_account/x\n"
        yield Shape(f"url-punctuation:{scheme}:{punctuation}:{root}", text, ())

    # Inner-component productions include both raw and resolved home pairs.
    for left, root, (name, private), tail in product(
            ("", "gcc -I", "ld -L"),
            ("/home//", "/home/./", "/x/../home/", "x/../home/",
             "name.ext/home/", "/home/removed/../"), names, ("/x", "/..", "/../y")):
        prefix = root + name
        # The raw 'removed' account remains private even when the resolved one is generic.
        end = len(prefix) if private else len("/home/removed")
        resolved_private = tail == "/../y"
        if resolved_private:
            end = len(prefix + tail)
        spans = ((len(left), len(left) + end),) if (
            private or resolved_private or root == "/home/removed/../") else ()
        yield Shape(f"inner:{left}:{root}:{name}:{tail}", left + prefix + tail + "\n", spans)

    for scheme, (name, private) in product(("file:", "File:", "FILE:"), names):
        prefix = "home/" + name
        spans = ((len(scheme), len(scheme) + len(prefix)),) if private else ()
        yield Shape("file-relative:" + scheme + name, scheme + prefix + "/x\n", spans)

    for text in ("/home%2Fprivate_account/x\n", r"C:\Users\private_account\x" + "\n",
                 "takes ~seconds.\n", "~1400 records\n"):
        yield Shape("declared-limit-or-prose:" + text, text, ())
