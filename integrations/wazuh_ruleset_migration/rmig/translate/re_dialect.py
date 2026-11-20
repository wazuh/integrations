"""Validator of the ``|re`` dialect of the live detector.

Security Analytics compiles a Sigma ``|re`` value into a whole-term Lucene
regexp, doubles every backslash and reads ``^``/``$`` as literals; a literal
space or ``/`` never matches, and a ``-`` closing a bracket is an invalid range
(checked against a live detector). So an emitted value has:

* no ``\\``, no ``$``, no ``^`` except right after ``[`` (negated class);
* no whitespace and no ``/``;
* a hyphen inside a class only as its first character or as a range between
  two characters (never ``-]``);
* balanced brackets and parentheses.

This is the last barrier before a rule is written: :func:`problems` returns why
a value is refused and the translator never emits a value it refuses.
"""


def problems(value):
    """List of problems of ``value`` as an emitted ``|re`` (empty when valid)."""
    out = []
    if not isinstance(value, str):
        return ["not a string"]
    if value == "":
        out.append("empty value")
    if "\\" in value:
        out.append("backslash")
    if "$" in value:
        out.append("'$' (read as a literal by the detector)")
    if "/" in value:
        out.append("'/' (never matches in the detector)")
    if any(ch.isspace() for ch in value):
        out.append("whitespace (never matches in the detector)")
    depth = 0
    in_class = False
    class_pos = 0
    prev = ""
    for i, ch in enumerate(value):
        if in_class:
            if ch == "]" and class_pos > 0:
                if prev == "-" and class_pos > 1:
                    out.append("'-]' at offset %d (invalid range)" % i)
                in_class = False
            elif ch == "^":
                if not (class_pos == 0):
                    out.append("'^' inside a class at offset %d" % i)
            elif ch == "-":
                first = class_pos == 0 or (class_pos == 1 and value[i - 1] == "^")
                if not first:
                    nxt = value[i + 1] if i + 1 < len(value) else ""
                    if nxt in ("", "]") or prev == "-":
                        out.append("'-' not first in a class at offset %d" % i)
            elif ch == "[":
                pass
            class_pos += 1
            prev = ch
            continue
        if ch == "[":
            in_class = True
            class_pos = 0
            prev = ""
            continue
        if ch == "^":
            out.append("'^' outside a negated class at offset %d" % i)
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                out.append("unbalanced ')' at offset %d" % i)
                depth = 0
        elif ch == "]":
            out.append("unbalanced ']' at offset %d" % i)
        prev = ch
    if in_class:
        out.append("unclosed class")
    if depth:
        out.append("unbalanced '('")
    return out


def valid(value):
    return not problems(value)
