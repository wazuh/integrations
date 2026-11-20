"""Parser of 4.14 decoder files (``wazuh@4.14.13:src/analysisd/decoders/decode-xml.c``)."""

from .. import model4 as m
from .xmlreader import read_xml

_PREMATCH_OFFSETS = ("after_parent",)
_REGEX_OFFSETS = ("after_parent", "after_prematch", "after_regex")


def _text(node):
    return node.text if node.text is not None else ""


def parse_decoder(node, rel):
    dec = {
        "kind": m.DECODER,
        "file": rel,
        "line": node.line,
        "name": None,
        "parent": None,
        "program_name": None,
        "prematch": None,
        "regex": None,
        "order": [],
        "fts": [],
        "ftscomment": None,
        "plugin_decoder": None,
        "use_own_name": False,
        "json_null_field": None,
        "json_array_structure": None,
        "accumulate": False,
        "type": None,
        "unknown": [],
        "invalid": [],
    }
    for key, value in node.attrs:
        k = key.lower()
        if k == "name":
            dec["name"] = value
        elif k == "status":
            pass  # read and discarded (dx:251-270)
        else:
            dec["unknown"].append({"line": node.line, "element": "@" + key})
    if not dec["name"]:
        dec["invalid"].append({"line": node.line, "message": "decoder without name"})
        dec["name"] = ""

    for child in node.children:
        tag = child.tag.lower()
        text = _text(child)
        t = (child.attr("type") or "").strip().lower() or None
        if tag == "parent":
            dec["parent"] = text.strip()
        elif tag == "program_name":
            eng = t or "osmatch"
            if eng not in m.ENGINES:
                dec["invalid"].append({"line": child.line, "message": "invalid type '%s'" % eng})
                eng = "osmatch"
            dec["program_name"] = {"value": text, "engine": eng, "line": child.line}
        elif tag == "prematch":
            eng = t or "osregex"
            if eng == "osmatch" or eng not in m.ENGINES:
                eng = "osregex"  # dx:368-400: warning, back to osregex
            offset = child.attr("offset")
            if offset is not None and offset not in _PREMATCH_OFFSETS:
                dec["invalid"].append({"line": child.line, "message": "invalid prematch offset '%s'" % offset})
            if dec["prematch"] is None:
                dec["prematch"] = {"value": text, "engine": eng, "offset": offset, "line": child.line}
            else:
                dec["prematch"]["value"] += text
                dec["prematch"]["engine"] = eng
        elif tag == "regex":
            eng = t or "osregex"
            if eng == "osmatch" or eng not in m.ENGINES:
                eng = "osregex"
            offset = child.attr("offset")
            if offset is not None and offset not in _REGEX_OFFSETS:
                dec["invalid"].append({"line": child.line, "message": "invalid regex offset '%s'" % offset})
            if dec["regex"] is None:
                dec["regex"] = {"value": text, "engine": eng, "offset": offset, "line": child.line}
            else:
                dec["regex"]["value"] += text  # only the first one may carry an offset
                dec["regex"]["engine"] = eng
        elif tag == "order":
            dec["order"] = [f.strip() for f in text.split(",") if f.strip()]
        elif tag == "fts":
            dec["fts"] = [f.strip() for f in text.split(",") if f.strip()]
        elif tag == "ftscomment":
            dec["ftscomment"] = text
        elif tag == "plugin_decoder":
            plugin = text.strip()
            if plugin not in m.DECODER_PLUGINS:
                dec["invalid"].append({"line": child.line, "message": "unknown plugin '%s'" % plugin})
            dec["plugin_decoder"] = {"value": plugin, "offset": child.attr("offset")}
        elif tag == "use_own_name":
            dec["use_own_name"] = text == "true"
        elif tag == "json_null_field":
            dec["json_null_field"] = text.strip()
        elif tag == "json_array_structure":
            dec["json_array_structure"] = text.strip()
        elif tag == "accumulate":
            dec["accumulate"] = True
        elif tag == "type":
            dec["type"] = text.strip()
            if dec["type"] not in m.DECODER_TYPES:
                dec["invalid"].append({"line": child.line, "message": "invalid type '%s'" % dec["type"]})
        else:
            dec["unknown"].append({"line": child.line, "element": child.tag})

    # structure checks (dx:691-702)
    if dec["parent"] is None and dec["prematch"] is None and dec["program_name"] is None:
        dec["invalid"].append({"line": node.line, "message": "root decoder without prematch or program_name"})
    if dec["regex"] is not None and not dec["order"]:
        dec["invalid"].append({"line": node.line, "message": "<regex> without <order>"})
    if dec["order"] and dec["regex"] is None:
        dec["invalid"].append({"line": node.line, "message": "<order> without <regex>"})
    if dec["plugin_decoder"] is not None and dec["regex"] is not None:
        dec["invalid"].append({"line": node.line, "message": "plugin_decoder together with regex"})
    return dec


def parse_decoders_text(text, rel):
    """Parse the text of a decoders file. Returns (decoders, file_problems)."""
    roots, variables, errors = read_xml(text)
    problems = {"errors": [e.as_dict() for e in errors], "unknown": [], "variables": sorted(variables)}
    decoders = []
    for root in roots:
        tag = root.tag.lower()
        if tag == "var":
            continue
        if tag == "decoder":
            decoders.append(parse_decoder(root, rel))
        else:
            problems["unknown"].append({"line": root.line, "element": root.tag})
    return decoders, problems
