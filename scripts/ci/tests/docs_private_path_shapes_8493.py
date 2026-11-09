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
            # Round 7 F2: only the path after the authority is the private prefix.
            start -= 1
        if context in ("file", "file-upper") and not root.startswith("/") and root != "~":
            # A home-root authority is still detected; only its path tail is repaired.
            start += root.index("/")
        spans = ((start, len(left) + len(prefix)),) if private and not public_web else ()
        yield Shape(f"{root}:{name}:{context}:{right!r}", text, spans)

    # Round 6 L1: URL-legal internal punctuation is public, including query/fragment text.
    for scheme, punctuation, root in product(
            ("http", "https", "HTTP", "HTTPS"), "+:@;=!$&*?#", roots):
        if root == "~":
            continue
        text = scheme + "://host/a" + punctuation + "b/" + root + "private_account/x\n"
        yield Shape(f"url-punctuation:{scheme}:{punctuation}:{root}", text, ())

    # Round 7 F1: independently declared complement cases for gate URL_TOKEN_CHARS.
    terminators = "".join(map(chr, range(32))) + "\x7f\u200b\u200c\u200d\ufeff<>`|\\^{}"
    for scheme, terminator, root in product(("http", "https", "HTTP", "HTTPS"),
                                           terminators, roots):
        left = scheme + "://host/a" + terminator
        prefix = root + "private_account"
        yield Shape(f"url-terminator:{scheme}:{terminator!r}:{root}",
                    left + prefix + "/x", ((len(left), len(left + prefix)),))

    # Round 7 F2: own literals, independent of gate WEB_URL_SCHEMES.
    for scheme, authority, root in product(
            ("ssh", "SSH", "sftp", "SFTP", "rsync", "RSYNC", "git+ssh", "GIT+SSH"),
            ("host", "user@host", "host:22", "user@host:22", ""),
            ("/home/", "/Users/", "/var/home/", "/mnt/c/Users/")):
        left = scheme + "://" + authority
        prefix = root + "private_account"
        yield Shape(f"authority:{scheme}:{authority}:{root}", left + prefix + "/x",
                    ((len(left), len(left + prefix)),))

    # Round 7 F3: own switch grammar, independent of gate PATH_SWITCHES.
    for switch, root in product(("-isystem", "-iquote", "-idirafter", "-F"),
                                ("home/", "Users/", "./home/", "../home/",
                                 "var/home/", "mnt/c/Users/")):
        left = "gcc " + switch
        prefix = root + "private_account"
        yield Shape(f"generic-switch:{switch}:{root}", left + prefix + "/i",
                    ((len(left), len(left + prefix)),))

    # Round 8 F1: retain the unmasked home-root authority productions.
    non_web = ("file", "FILE", "fIlE", "ssh", "SSH", "sftp", "SFTP", "smb", "rsync")
    for scheme, user, root, (name, private) in product(
            non_web, ("", "u@"), ("home", "Users"), names):
        left = scheme + "://" + user + root
        prefix = "/" + name
        spans = ((len(left), len(left + prefix)),) if private else ()
        yield Shape(f"home-authority:{scheme}:{user}:{root}:{name}",
                    left + prefix + "/x", spans)

    # Round 8 F2: authority bytes are independent of the web-token alphabet.
    authorities = ("[::1]", "[::1]:22", "user@[::1]:22", "[2001:db8::1]:2222",
                   "ho\u200bst", "ho\u200cst", "ho\u200dst", "ho\ufeffst")
    for scheme, authority, root in product(non_web, authorities, ("/home/", "/Users/")):
        left = scheme + "://" + authority
        prefix = root + "private_account"
        yield Shape(f"authority-bytes:{scheme}:{authority}:{root}", left + prefix + "/x",
                    ((len(left), len(left + prefix)),))

    # Round 8 F3: nested schemes keep both authorities and the inner path separator.
    for outer, inner, authority, root in product(
            non_web, ("http", "HTTPS", "ssh", "SFTP"),
            ("host", "user@host:22", "[::1]:22"), ("home/", "Users/")):
        left = outer + "://outer/" + inner + "://" + authority + "/"
        prefix = root + "private_account"
        yield Shape(f"nested-scheme:{outer}:{inner}:{authority}:{root}",
                    left + prefix + "/x", ((len(left), len(left + prefix)),))

    # Round 8 F4/F5: independent option spellings, never scanner constants.
    for switch, root in product(("--sysroot", "-m64", "-x-y", "-I-"),
                                ("/home/", "/Users/", "/var/home/", "/mnt/c/Users/")):
        left = "gcc " + switch
        prefix = root + "private_account"
        yield Shape(f"dash-switch:{switch}:{root}", left + prefix + "/x",
                    ((len(left), len(left + prefix)),))
    for switch, (name, private), right in product(
            ("-isystem", "-iquote", "-idirafter", "-F"), names, ("", "/inc")):
        left = "gcc " + switch
        prefix = "~" + name
        spans = ((len(left), len(left + prefix)),) if private else ()
        yield Shape(f"tilde-switch:{switch}:{name}:{right}", left + prefix + right, spans)

    # Round 9 F1: local path nesting is private; standalone web boundaries stay public.
    for local, scheme, root, (name, private) in product(
            ("cache/", "/srv/mirror/", "~/"), ("http", "https", "HTTP", "HTTPS"),
            ("h/home/", "h/Users/", "home/", "Users/"), names):
        authority, path = root.split("/", 1)
        left = local + scheme + "://" + authority + "/"
        prefix = path + name
        spans = ((len(left), len(left + prefix)),) if private else ()
        yield Shape(f"local-web:{local}:{scheme}:{root}:{name}",
                    left + prefix + "/x", spans)
    for left, scheme, root in product(
            ("", " ", "(", "[", '"', "'", ",", "[label]("),
            ("http", "https", "HTTP", "HTTPS"), ("home/", "Users/")):
        text = left + scheme + "://h/" + root + "private_account/x"
        yield Shape(f"public-web-boundary:{left}:{scheme}:{root}", text, ())

    # Round 10 F1: independent literals for the gate's INVISIBLE set.
    for local, invisible, scheme, root, (name, private) in product(
            ("cache/", "/srv/mirror/", "~/"), "\u200b\u200c\u200d\ufeff",
            ("http", "https", "HTTP"), ("h/home/", "h/Users/", "home/", "Users/"), names):
        authority, path = root.split("/", 1)
        left = local + invisible + scheme + "://" + authority + "/"
        prefix = path + name
        spans = ((len(left), len(left + prefix)),) if private else ()
        yield Shape(f"invisible-local-web:{local}:{invisible!r}:{scheme}:{root}:{name}",
                    left + prefix + "/x", spans)

    # Round 10 F2: a tilde before a web header cannot consume the header as an account.
    for scheme, root, (name, private) in product(
            ("http", "https", "HTTP"), ("h/home/", "h/Users/", "home/", "Users/"), names):
        authority, path = root.split("/", 1)
        left = "~" + scheme + "://" + authority + "/"
        prefix = path + name
        spans = ((len(left), len(left + prefix)),) if private else ()
        yield Shape(f"tilde-web:{scheme}:{root}:{name}", left + prefix + "/x", spans)

    # Round 11 F1: a scheme-looking suffix does not make an account a web header.
    # Round 12 INFO: near-miss web names and both library/generic option prefixes.
    for (left, closing), name, tail in product(
            (("", ""), ("see ", ""), ("`", "`"), ("-I", ""), ("-L", ""),
             ("--sysroot", ""), ("/srv/", "")),
            ("private_account", "private\u200bq", "private_account.x", "https2", "httpsx"),
            ("://h/x", ":///x", "://")):
        prefix = "~" + name
        yield Shape(f"tilde-non-web:{left}:{name!r}:{tail}",
                    left + prefix + tail + closing, ((len(left), len(left + prefix)),))
    # Independent literals for the gate's WEB_URL_SCHEMES; valid headers are public twins.
    for (left, closing), scheme, tail in product(
            (("", ""), ("see ", ""), ("`", "`"), ("-I", ""), ("-L", ""),
             ("--sysroot", ""), ("/srv/", "")),
            ("http", "https", "HTTP", "HTTPS"), ("://h/x", ":///x", "://")):
        yield Shape(f"tilde-web-public:{left}:{scheme}:{tail}",
                    left + "~" + scheme + tail + closing, ())

    # Round 12 F1: slash-backed named homes apply anywhere, preserving their left bytes.
    for (left, tail), (name, private) in product(
            (("~", "/x"), ("~~", "/x~~"), ("/srv/~", "/x"),
             ("a", "/x"), ("_", "/x"), ("9", "/x")), names):
        prefix = "~" + name
        spans = ((len(left), len(left + prefix)),) if private else ()
        yield Shape(f"glued-named-home:{left}:{name}:{tail}", left + prefix + tail, spans)
    for text in ("~~word~~", "v1~", "abc~", "~~was here~~"):
        yield Shape("glued-tilde-public:" + text, text, ())
    prefix = "~private_account"
    yield Shape("hyphen-named-home-control", "a-" + prefix + "/x",
                ((len("a-"), len("a-" + prefix)),))

    # Round 11 F2: original INVISIBLE bytes break the header into two private prefixes.
    for left, scheme, invisible, root in product(
            ("", "-I", "/srv/"), ("http", "https", "HTTP", "HTTPS"),
            "\u200b\u200c\u200d\ufeff", ("/home/", "/Users/", "/var/home/")):
        account = "~" + scheme + invisible
        path = "//h" + root + "private_account"
        path_start = len(left + account + ":")
        yield Shape(f"tilde-broken-web:{left}:{scheme}:{invisible!r}:{root}",
                    left + account + ":" + path + "/x",
                    ((len(left), len(left + account)), (path_start, path_start + len(path))))

    # Round 9 F2: independent dash-token and embedded PATH_SWITCHES spellings.
    for switch, (name, private), tail in product(
            ("--sysroot", "-m64", "-x-y", "--include", "-I-", "x-I", "x-L", "foo-I", "--I"),
            names, ("", "/inc")):
        prefix = "~" + name
        spans = ((len(switch), len(switch + prefix)),) if private else ()
        yield Shape(f"dash-word-tilde:{switch}:{name}:{tail}",
                    switch + prefix + tail, spans)

    # Round 9 F2: option spellings inside an account never become option prefixes.
    for root, switch in product(("/home/", "home/", "local/Users/"), ("-I", "-L")):
        prefix = root + "private" + switch + "account"
        yield Shape(f"account-option-text:{root}:{switch}", prefix + "/x",
                    ((0, len(prefix)),))

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
        start = len(left)
        if left and root in ("name.ext/home/", "x/../home/"):
            # Round 8 F4: this component is part of the leading dash token.
            start += len(root.split("/", 1)[0])
        spans = ((start, len(left) + end),) if (
            private or resolved_private or root == "/home/removed/../") else ()
        yield Shape(f"inner:{left}:{root}:{name}:{tail}", left + prefix + tail + "\n", spans)

    for scheme, (name, private) in product(("file:", "File:", "FILE:"), names):
        prefix = "home/" + name
        spans = ((len(scheme), len(scheme) + len(prefix)),) if private else ()
        yield Shape("file-relative:" + scheme + name, scheme + prefix + "/x\n", spans)

    for text in ("/home%2Fprivate_account/x\n", r"C:\Users\private_account\x" + "\n",
                 "takes ~seconds.\n", "~1400 records\n"):
        yield Shape("declared-limit-or-prose:" + text, text, ())
