"""Values copied from the input (descriptions, decoder and list names, server messages) on their way to Markdown
or to the terminal: they must not add HTML, links or images to a report, nor escape sequences to a terminal."""

import re

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_MD = {"|": "\\|", "<": "&lt;", ">": "&gt;", "[": "\\[", "]": "\\]"}


def plain(text):
    """``text`` with every C0/C1 control character (tab and newline kept) shown as a ``\\xNN`` escape."""
    return _CONTROL.sub(lambda m: "\\x%02x" % ord(m.group(0)), "" if text is None else str(text))


def md(text):
    """``text`` as one line of Markdown: no raw HTML (``<`` ``>``), no link or image syntax (``[`` ``]``), ``|``
    escaped for table cells, newlines folded, control characters shown."""
    s = plain(text).replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return "".join(_MD.get(c, c) for c in s)
