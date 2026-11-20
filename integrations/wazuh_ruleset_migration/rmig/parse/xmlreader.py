"""Tolerant reader for the XML dialect of Wazuh 4.x (``os_xml``).

Wazuh 4.x rule and decoder files are not well-formed XML: they have several root
elements, comments anywhere, and bare ``&`` and escaped ``\\<`` inside patterns.
This reader follows ``wazuh@4.14.13:src/os_xml/os_xml.c``:

* ``<!`` starts a comment that ends at ``-->`` or ``!>``;
* a ``<`` preceded by an odd number of backslashes is content, and the
  backslashes are kept (OS_Regex reads ``\\<`` as a literal ``<``);
* no entity is decoded (``&lt;`` stays ``&lt;``);
* the content of an element with children is the text after its last child.

``<var name="X">`` definitions are applied as in
``wazuh@4.14.13:src/os_xml/os_xml_variables.c``: in document order, to element
contents and attribute values longer than two characters, with the variable
name ending at ``$ . | ,`` or a space.

Errors never raise: they are returned with their line so that the caller can
keep reading the rest of the file.
"""

import re

_NAME_END = re.compile(r"[\s>]")
_ATTR = re.compile(r"\s*([^\s=/>]+)\s*=\s*(\"[^\"]*\"|'[^']*')", re.S)


class Node:
    __slots__ = ("tag", "attrs", "text", "children", "line")

    def __init__(self, tag, line):
        self.tag = tag
        self.attrs = []  # list of [name, value]; order kept, duplicates kept
        self.text = None
        self.children = []
        self.line = line

    def attr(self, name, default=None):
        lname = name.lower()
        for key, value in self.attrs:
            if key.lower() == lname:
                return value
        return default

    def __repr__(self):  # pragma: no cover - debugging aid
        return "Node(%r, line=%d)" % (self.tag, self.line)


# 4.x os_xml stops at 1024 levels; Python's own recursion limit (1000) is below that, so the reader stops at 200
# levels (no real ruleset nests deeper than a few) with an error instead of a RecursionError.
MAX_DEPTH = 200


class XmlError:
    __slots__ = ("line", "message")

    def __init__(self, line, message):
        self.line = line
        self.message = message

    def as_dict(self):
        return {"line": self.line, "message": self.message}


class _Reader:
    def __init__(self, text):
        self._found = {}  # terminator -> next position found (see _next)
        self.s = text
        self.n = len(text)
        self.i = 0
        self.errors = []
        # line starts for fast line lookup
        self._nl = [m.start() for m in re.finditer("\n", text)]

    def line_at(self, pos):
        import bisect

        return bisect.bisect_left(self._nl, pos) + 1

    def _next(self, start, token):
        cache = self._found
        hit = cache.get(token)
        if hit is None or (hit != -1 and hit < start):
            hit = self.s.find(token, start)
            cache[token] = hit
        return hit

    def err(self, pos, msg):
        self.errors.append(XmlError(self.line_at(pos), msg))

    def skip_special(self, pos):
        """At ``pos`` there is a ``<``. Return the end of a comment or ``<?...?>``
        block that starts here, or -1 if it is not one."""
        s = self.s
        if s.startswith("<!", pos):
            start = pos + 2
            ends = []
            # each terminator is searched once from the current position and the answer kept: positions only
            # grow, so a file of many comments is read in linear time (no rescan to the end per comment)
            a = self._next(start, "-->")
            if a >= 0:
                ends.append(a + 3)
            b = self._next(start, "!>")
            if b >= 0:
                ends.append(b + 2)
            if not ends:
                self.err(pos, "comment not closed")
                return self.n
            return min(ends)
        if s.startswith("<?", pos):
            end = s.find("?>", pos + 2)
            if end < 0:
                self.err(pos, "processing instruction not closed")
                return self.n
            return end + 2
        return -1

    def find_tag_start(self, pos):
        """Next unescaped ``<`` from ``pos`` that is not a comment. Returns
        (index or -1, text_between) where comments are removed from the text."""
        s = self.s
        chunks = []
        cur = pos
        while True:
            j = s.find("<", cur)
            if j < 0:
                chunks.append(s[pos:])
                return -1, "".join(chunks)
            # count backslashes immediately before
            k = j - 1
            nb = 0
            while k >= pos and s[k] == "\\":
                nb += 1
                k -= 1
            special = self.skip_special(j)
            if special >= 0:
                chunks.append(s[pos:j])
                pos = cur = special
                continue
            if nb % 2 == 1:
                cur = j + 1
                continue
            chunks.append(s[pos:j])
            return j, "".join(chunks)

    def parse_open(self, pos):
        """Parse ``<name attrs>`` at ``pos``. Returns (node, end, selfclosed)."""
        s = self.s
        m = _NAME_END.search(s, pos + 1)
        if not m:
            self.err(pos, "element not closed")
            return None, self.n, True
        name = s[pos + 1:m.start()]
        selfclosed = False
        if name.endswith("/"):
            name = name[:-1]
            selfclosed = True
        node = Node(name, self.line_at(pos))
        end = m.start()
        if s[end] == ">":
            return node, end + 1, selfclosed
        # attributes
        close = s.find(">", end)
        if close < 0:
            self.err(pos, "element <%s> not closed" % name)
            return node, self.n, True
        # a '>' inside a quoted attribute value must not end the tag
        cur = end
        while True:
            m2 = _ATTR.match(s, cur)
            if not m2:
                break
            node.attrs.append([m2.group(1), m2.group(2)[1:-1]])
            cur = m2.end()
        rest_end = s.find(">", cur)
        if rest_end < 0:
            self.err(pos, "element <%s> not closed" % name)
            return node, self.n, True
        rest = s[cur:rest_end].strip()
        if rest == "/":
            selfclosed = True
        elif rest:
            self.err(pos, "invalid attribute text in <%s>: %r" % (name, rest[:40]))
            if rest.endswith("/"):
                selfclosed = True
        return node, rest_end + 1, selfclosed

    def parse_children(self, parent, pos, depth):
        """Read content and children of ``parent`` until its closing tag."""
        s = self.s
        text = ""
        while True:
            j, chunk = self.find_tag_start(pos)
            text += chunk
            if j < 0:
                self.err(self.n if parent is None else pos,
                         "end of file and element <%s> not closed" % parent.tag)
                parent.text = text
                return self.n, None
            if s.startswith("</", j):
                end = s.find(">", j)
                if end < 0:
                    self.err(j, "closing tag not finished")
                    parent.text = text
                    return self.n, None
                cname = s[j + 2:end].strip()
                parent.text = text
                if cname != parent.tag:
                    self.err(j, "element <%s> closed by </%s>" % (parent.tag, cname))
                    return end + 1, cname
                return end + 1, None
            node, pos, selfclosed = self.parse_open(j)
            if node is None:
                parent.text = text
                return pos, None
            parent.children.append(node)
            text = ""  # os_xml keeps only the text after the last child
            if selfclosed:
                node.text = ""
                continue
            if depth > MAX_DEPTH:
                self.err(j, "max recursion level reached")
                return self.n, None
            pos, mismatch = self.parse_children(node, pos, depth + 1)
            if mismatch is not None:
                # recovery: the closing tag belongs to an ancestor
                if mismatch == parent.tag:
                    parent.text = text
                    return pos, None
                # unknown closing tag: ignore it and continue

    def parse(self):
        roots = []
        pos = 0
        s = self.s
        while True:
            j, chunk = self.find_tag_start(pos)
            if j < 0:
                break
            if s.startswith("</", j):
                end = s.find(">", j)
                self.err(j, "element not opened: %s" % s[j:end + 1 if end >= 0 else j + 20])
                pos = end + 1 if end >= 0 else self.n
                continue
            node, pos, selfclosed = self.parse_open(j)
            if node is None:
                break
            roots.append(node)
            if selfclosed:
                node.text = ""
                continue
            pos, mismatch = self.parse_children(node, pos, 1)
        return roots


def _substitute(value, variables, line, errors):
    """Apply ``$VAR`` substitution like OS_ApplyVariables."""
    if value is None or len(value) <= 2 or not variables or "$" not in value:
        return value
    out = []
    i = 0
    n = len(value)
    while i < n:
        c = value[i]
        if c != "$":
            out.append(c)
            i += 1
            continue
        j = i + 1
        while j < n and value[j] not in "$.|, ":
            j += 1
        name = value[i + 1:j]
        repl = variables.get(name.lower())
        if repl is not None:
            out.append(repl)
            i = j
            continue
        if name and not name.startswith("("):
            errors.append(XmlError(line, "unknown variable: '%s'" % name[:95]))
        out.append(value[i:j])
        i = j
    return "".join(out)


def apply_variables(roots, errors):
    """Collect ``<var>`` and substitute them in document order. Returns the
    variable map (lower-case names)."""
    variables = {}

    def walk(node):
        if node.tag.lower() == "var":
            name = node.attr("name")
            if name is None or node.text is None:
                errors.append(XmlError(node.line, "variable without name or value"))
            else:
                variables[name.lower()] = node.text
            return
        for pair in node.attrs:
            pair[1] = _substitute(pair[1], variables, node.line, errors)
        if node.text is not None:
            node.text = _substitute(node.text, variables, node.line, errors)
        for child in node.children:
            walk(child)

    for root in roots:
        walk(root)
    return variables


def read_xml(text):
    """Parse ``text``. Returns (roots, variables, errors)."""
    if text.startswith("﻿"):
        text = text[1:]
    reader = _Reader(text)
    roots = reader.parse()
    errors = list(reader.errors)
    variables = apply_variables(roots, errors)
    errors.sort(key=lambda e: e.line)
    return roots, variables, errors
