"""The ``<ruleset>`` block of ``ossec.conf`` (``wazuh@4.14.13:src/config/rules-config.c``)."""

import re

from .xmlreader import read_xml

RULESET_ELEMENTS = (
    "rule_include", "rule_dir", "rule_exclude", "list", "decoder_include",
    "decoder_dir", "decoder_exclude",
)

# etc/templates/config/generic/rules.template (and etc/ossec.conf:233-246 of 4.14.13)
DEFAULT_RULESET = [
    ["decoder_dir", "ruleset/decoders", {}],
    ["rule_dir", "ruleset/rules", {}],
    ["rule_exclude", "0215-policy_rules.xml", {}],
    ["list", "etc/lists/audit-keys", {}],
    ["list", "etc/lists/amazon/aws-eventnames", {}],
    ["list", "etc/lists/security-eventchannel", {}],
    ["list", "etc/lists/malicious-ioc/malware-hashes", {}],
    ["list", "etc/lists/malicious-ioc/malicious-ip", {}],
    ["list", "etc/lists/malicious-ioc/malicious-domains", {}],
    ["decoder_dir", "etc/decoders", {}],
    ["rule_dir", "etc/rules", {}],
]


def _no_excerpt(error):
    """An XML error of ossec.conf without the text it quotes (it could be a secret)."""
    error["message"] = re.sub(r"^(invalid attribute text in <[^>]*>|element not opened).*", r"\1", error["message"],
                              flags=re.S)
    return error


def parse_ossec_conf(text):
    """Return (config, problems). ``config`` is a RulesetConfig4 dict built from
    every ``<ruleset>`` block in order (analysisd reads them all)."""
    roots, _vars, errors = read_xml(text)
    problems = {"errors": [_no_excerpt(e.as_dict()) for e in errors], "unknown": []}
    directives = []
    found = False

    def visit(node):
        nonlocal found
        if node.tag == "ruleset":
            found = True
            for child in node.children:
                if child.tag in RULESET_ELEMENTS:
                    attrs = {k.lower(): v for k, v in child.attrs}
                    directives.append([child.tag, (child.text or "").strip(), attrs])
                else:
                    problems["unknown"].append({"line": child.line, "element": child.tag})
            return
        for child in node.children:
            visit(child)

    for root in roots:
        visit(root)
    if not found:
        return {"directives": [list(d) for d in DEFAULT_RULESET], "origin": "default"}, problems
    return {"directives": directives, "origin": "ossec.conf"}, problems


def default_config():
    return {"directives": [[a, b, dict(c)] for a, b, c in DEFAULT_RULESET], "origin": "default"}


# Blocks of ossec.conf outside <ruleset> that the report reads (references, completeness). Read only.
OUTPUT_BLOCKS = ("active-response", "command", "integration", "email_alerts", "alerts", "reports", "global",
                 "localfile", "wodle", "syslog_output")


# Element names (last part of ``parent.child``) and attribute names whose value is a secret: masked when read, so
# no copy of the block (work/inventory.json, report.json, out/references/) holds it.
# A name is secret when any part of it says so (``account_key``, ``sas_token``, ``secret_value``, ``auth_path``):
# a name the list does not know fails closed.
SECRET_TAG = re.compile(r"pass|secret|token|key|auth|cred|hook|^options$", re.I)
MASK = "***"
MASK_EMAIL = "<email address>"
# Command lines and their extra arguments: masked fail-closed (mask_command).
COMMAND_TAG = ("command", "full_command", "extra_args")
_URL = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)([^\s/?#@]*@)?([^\s/?#]*)([^\s]*)")


def mask_urls(text):
    """Every URL in ``text`` without its user information and without its path and query (a webhook path is
    its secret): ``https://u:p@host/a?b`` -> ``https://***@host/***``."""

    def sub(m):
        rest = m.group(4)
        return "%s%s%s%s" % (m.group(1), "***@" if m.group(2) else "", m.group(3),
                             "/" + MASK if rest not in ("", "/") else rest)

    return _URL.sub(sub, text)


# Command lines are masked fail-closed: the program, short flags (``-e``), long flags without a value
# (``--header``) and file paths stay (the report uses a list path named in a refresh script); every other
# argument becomes ``***``, so a password, a token, a header or a JSON body never survives in any form.
# A path is kept only under a well-known root or ``etc/``: ``user/password`` and a base64 key hold a slash too.
_PLAIN_PATH = re.compile(r"^(/(var|etc|usr|opt|home|tmp|bin|sbin|srv|mnt|run|root|lib|lib64|dev|proc)|\.{0,2}/?etc)"
                         r"(/[A-Za-z0-9_.-]+)*/?$")
_PLAIN_FLAG = re.compile(r"^(-[A-Za-z]|--[A-Za-z][A-Za-z-]*)$")
_PROGRAM = re.compile(r"^[A-Za-z0-9_./-]+$")
_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=")


def _tokens(text):
    import shlex

    try:
        return shlex.split(text)
    except ValueError:  # unbalanced quotes
        return text.split()


def mask_command(text, has_program=True):
    """A command line with only its program, plain flags and plain paths kept; every other argument is ``***``
    and an environment assignment keeps its name only (``PGPASSWORD=***``). ``has_program`` False: ``text`` is
    a list of arguments (``<extra_args>``), so its first word is masked like the others."""
    out, program = [], None if has_program else ""
    for tok in _tokens(text):
        m = _ASSIGN.match(tok)
        if program is None and m:
            out.append(m.group(1) + "=" + MASK)
            continue
        if program is None:
            program = tok
            out.append(tok if _PROGRAM.match(tok) else MASK)
            continue
        out.append(tok if _PLAIN_FLAG.match(tok) or _PLAIN_PATH.match(tok) else MASK)
    return " ".join(out)


def mask_value(name, text):
    """The value of the element or attribute ``name`` as the tool keeps it."""
    if not text:
        return text
    last = name.rsplit(".", 1)[-1].lower()
    if SECRET_TAG.search(last):
        return MASK
    if last == "email_to":
        return MASK_EMAIL
    if last in COMMAND_TAG:
        text = mask_command(text, has_program=last != "extra_args")
    return mask_urls(text)


def _attrs(node):
    return {k.lower(): mask_value(k, v) for k, v in node.attrs}


def _text(tag, node):
    return mask_value(tag, (node.text or "").strip())


def _flat(node):
    out = []
    for child in node.children:
        attrs = _attrs(child)
        if child.children:
            for sub in child.children:
                tag = "%s.%s" % (child.tag, sub.tag)
                out.append([tag, _text(tag, sub), _attrs(sub)])
        else:
            out.append([child.tag, _text(child.tag, child), attrs])
    return out


def parse_conf_blocks(text, path):
    """``{"file", "blocks": [...], "sections": {tag: count}}`` for one ossec.conf.

    Each block: ``{"kind", "file", "line", "attrs", "elements": [[tag, text, attrs], ...]}`` (children one level
    deep; a grandchild is ``parent.child``). ``sections`` counts every top-level element of ``<ossec_config>``.
    Comments are skipped by the reader, so a commented-out block is not read."""
    roots, _vars, _errors = read_xml(text)
    blocks, sections = [], {}

    def take(node):
        tag = node.tag.lower()
        sections[tag] = sections.get(tag, 0) + 1
        if tag in OUTPUT_BLOCKS:
            blocks.append({"kind": tag, "file": path, "line": node.line,
                           "attrs": _attrs(node), "elements": _flat(node)})

    for root in roots:
        if root.tag.lower() == "ossec_config":
            for child in root.children:
                take(child)
        else:
            take(root)
    return {"file": path, "blocks": blocks, "sections": dict(sorted(sections.items()))}
