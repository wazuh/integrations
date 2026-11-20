"""File-system helpers with a stable order: never depend on ``os.listdir`` order."""

import os


def listdir_sorted(path):
    try:
        names = os.listdir(path)
    except (FileNotFoundError, NotADirectoryError):
        return []
    return sorted(names)


def inside(root, path):
    """True when ``path``, symbolic links resolved, is ``root`` or under it."""
    r = os.path.realpath(root)
    p = os.path.realpath(path)
    try:
        return os.path.commonpath([r, p]) == r
    except ValueError:  # another drive on Windows
        return False


def walk_files(root, skipped=None):
    """Relative paths (``/`` separated) of every regular file under ``root``,
    sorted, skipping ``.git``. A file or directory whose symbolic link points
    outside ``root`` is left out (and its relative path added to ``skipped``)."""
    out = []

    def rec(rel):
        full = os.path.join(root, rel) if rel else root
        for name in listdir_sorted(full):
            if name == ".git":
                continue
            r = rel + "/" + name if rel else name
            p = os.path.join(root, r)
            if os.path.islink(p) and not inside(root, p):
                if skipped is not None:
                    skipped.append(r)
                continue
            if os.path.isdir(p) and not os.path.islink(p):
                rec(r)
            elif os.path.isfile(p):
                out.append(r)

    if os.path.isdir(root):
        rec("")
    return sorted(out)


def read_text(path):
    with open(path, "rb") as fh:
        data = fh.read()
    return data.decode("utf-8", "replace").replace("\r\n", "\n")


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()
