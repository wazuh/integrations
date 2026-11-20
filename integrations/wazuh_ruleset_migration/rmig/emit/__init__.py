"""Write ``out/`` exactly as the layout shared between ``build`` and
``apply``/``verify``/``activate`` fixes it.

JSON is UTF-8 with sorted keys, indentation 2 and a final newline
(:func:`rmig.jsonio.dumps`); ``out/`` is rebuilt from scratch on every build
so that two builds of the same input give the same bytes.
"""

import csv
import io
import os
import shutil

from .. import __version__
from ..jsonio import dumps, write_text
from ..translate.meta import MARKER_AUTHOR, safe_name

FORMAT = 1
MAPPING_FIELDS = ["rule_id_4x", "state", "reasons", "integration", "resource_title", "local_id", "server_id"]


def render(package, inv):
    """{relative path under out/: text}."""
    files = {}
    keys = package.ordered_keys()
    files["manifest.json"] = dumps({
        "format": FORMAT,
        "tool_version": __version__,
        "source": inv["source"]["name"],
        "marker_author": MARKER_AUTHOR,
        "root_decoder": package.root,
        "engine_helpers": package.engine_helpers,
        "integrations": keys,
    })
    for key in keys:
        integ = package.integrations[key]
        base = "integrations/%s/" % key
        files[base + "integration.json"] = dumps(integ["doc"])
        for title in sorted(integ["kvdbs"]):
            files[base + "kvdbs/%s.json" % safe_name(title)] = dumps(integ["kvdbs"][title])
        width = max(2, len(str(len(integ["decoders"]))))
        for n, doc in enumerate(integ["decoders"], start=1):
            name = doc["resource"]["name"].split("/")[1]
            files[base + "decoders/%0*d-%s.json" % (width, n, safe_name(name))] = dumps(doc)
        for rid in sorted(integ["rules"], key=lambda x: int(x)):
            files[base + "rules/%s.json" % rid] = dumps(integ["rules"][rid])
    for rid, body in package.monitors.items():
        files["monitors/%s.json" % rid] = dumps(body)
    for name, text in package.recipes.items():
        files["recipes/%s" % name] = text
    for name, doc in package.detectors.items():
        files["detectors/%s" % name] = dumps(doc)
    files["mapping.json"] = dumps({"format": FORMAT, "fields": MAPPING_FIELDS, "rows": package.mapping})
    buf = io.StringIO()
    wr = csv.writer(buf, lineterminator="\n")
    wr.writerow(MAPPING_FIELDS)
    for row in package.mapping:
        wr.writerow([";".join(row[f]) if isinstance(row[f], list) else row[f] for f in MAPPING_FIELDS])
    files["mapping.csv"] = buf.getvalue()
    return files


class UnsafePath(Exception):
    """A file of ``out/`` would land outside ``out/`` (protective stop ``RM-P-UNSAFE-PATH``)."""


def unsafe_part(rel):
    """Why the relative path ``rel`` (``/`` separated) is not a plain path under its base, or None.

    Pure: the same answer on every OS. A part that is empty, ``.`` or ``..``, or that holds a backslash or ``:``
    (a Windows separator, a drive such as ``C:`` or an alternate data stream) is refused, and so is a control
    character."""
    if not isinstance(rel, str) or not rel or rel.startswith("/"):
        return "not a relative path"
    for part in rel.split("/"):
        if part in ("", ".", ".."):
            return "the part %r is not a name" % part
        if "\\" in part or ":" in part:
            return "the part %r holds a path separator or a drive" % part
        if any(ord(c) < 32 or ord(c) == 127 for c in part):
            return "the part %r holds a control character" % part
    return None


def check_paths(out_dir, files):
    """Raise :class:`UnsafePath` unless every file of ``files`` resolves inside ``out_dir``. Called before
    anything is written or deleted."""
    root = os.path.realpath(out_dir)
    for rel in sorted(files):
        why = unsafe_part(rel)
        target = os.path.realpath(os.path.join(root, *rel.split("/")))
        if why is None and os.path.commonpath([root, target]) != root:
            why = "it resolves outside %s" % out_dir
        if why:
            raise UnsafePath("RM-P-UNSAFE-PATH: the output file %r was refused (%s); nothing was written" % (rel, why))


def write(out_dir, files):
    """Replace ``out_dir`` with exactly ``files``. An ``out_dir`` that holds files and is not an earlier
    output of the tool (no ``manifest.json``) is never deleted: :class:`UnsafePath`."""
    check_paths(out_dir, files)
    if os.path.isdir(out_dir):
        if os.listdir(out_dir) and not os.path.isfile(os.path.join(out_dir, "manifest.json")):
            raise UnsafePath("RM-P-UNSAFE-PATH: %s exists and is not an output of this tool (no manifest.json): "
                             "it was not replaced; choose another --workdir or remove it" % out_dir)
        shutil.rmtree(out_dir)
    for rel in sorted(files):
        write_text(os.path.join(out_dir, *rel.split("/")), files[rel])
    return len(files)
