"""Reproducibility check: the committed pack, alone, reproduces its unit tests and expected monitors.

Outer mode (run from any checkout):

    python tests/repro/check_clean_checkout.py --commit HEAD --out DIR

1. clones the repository (``git clone --no-local``) into a new temporary directory and checks out
   the commit detached, so only committed files exist there;
2. creates a new virtual environment and installs ``requirements.txt`` (needs PyPI or a pip cache);
3. runs the *clone's own copy* of this script (inner mode) with that interpreter, ``-E -s -B``,
   the clone's pack directory as working directory, an empty temporary home directory and no
   ``WCP_*``/``PYTHON*`` variables (no credentials, no deployment state, no user site-packages);
4. checks that the run wrote nothing into the clone or the home directory, and that the source
   checkout has no untracked or ignored files in the pack (files that exist locally but would be
   missing from a clean checkout).

Inner mode runs the unit tests in-process and then verifies that every ``wcp`` and test module was
loaded from the clone (never from the source checkout), runs the offline self-tests of the RC2
validation harness (``tests/validation/test_*.py``, when present) in a separate process and checks
that their modules load from the clone, runs ``wcp validate`` and ``wcp render``
and compares the rendered monitors byte for byte (with LF line endings, the committed form) with
``expected/monitors/``, compiles every
Python file, and checks that file references in the documentation resolve to tracked files.

Result: ``DIR/clean_checkout.json`` (paths relative to the clone; absolute local paths are not
recorded). Offline; no Wazuh or OpenSearch access. The temporary directory is deleted unless
``--keep`` is given.
"""

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

PACK_REL = "integrations/wazuh_correlation_pack"
CRED_NAME = re.compile(r"(\.env|\.pem|\.key|\.p12|\.pfx|manifest\.json)$|(^|/)state/", re.I)
DOC_REF = re.compile(r"(?<![\w$<{/.-])((?:\.\./)*(?:wcp|tests|docs|samples|expected|evidence|rules|correlations)"
                     r"/[\w./-]*[\w-])")


def git(repo, *args):
    return subprocess.run(["git", "-C", repo] + list(args), check=True, capture_output=True,
                          text=True).stdout.strip()


def remove_tree(path):
    """rmtree that also removes read-only files (git object files are read-only on Windows)."""
    def onerror(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if os.path.exists(path):
        shutil.rmtree(path, onerror=onerror)


def inside(path, root):
    p = os.path.normcase(os.path.realpath(path))
    r = os.path.normcase(os.path.realpath(root))
    return p == r or p.startswith(r + os.sep)


# --------------------------------------------------------------------------------------- outer
def outer(a):
    src_top = git(a.repo, "rev-parse", "--show-toplevel")
    sha = git(src_top, "rev-parse", a.commit + "^{commit}")
    tmp = tempfile.mkdtemp(prefix="wcp-clean-")
    res = {"tested_commit": sha, "checks": {}}
    try:
        clone = os.path.join(tmp, "src")
        subprocess.run(["git", "clone", "-q", "--no-local", "--no-checkout", src_top, clone], check=True)
        git(clone, "checkout", "-q", "--detach", sha)
        pack = os.path.join(clone, *PACK_REL.split("/"))
        res["revisions"] = {
            "tested_commit": sha,
            "detection_code": git(clone, "log", "-1", "--format=%H", "--", *["%s/%s" % (PACK_REL, p) for p in
                                  ("wcp", "rules", "correlations", "pack.yml")]),
            "expected_monitors": git(clone, "log", "-1", "--format=%H", "--", PACK_REL + "/expected/monitors"),
            "test_harness": git(clone, "log", "-1", "--format=%H", "--", PACK_REL + "/tests"),
        }
        tracked = git(clone, "ls-files", "--", PACK_REL).splitlines()
        cred = [t for t in tracked if CRED_NAME.search(t)]
        res["tracked_files"] = len(tracked)
        res["tracked_credential_or_state_names"] = cred
        res["checks"]["no_tracked_credentials_or_state"] = not cred
        # files present in the source checkout but absent from a clean checkout
        st = git(src_top, "status", "--porcelain", "--ignored", "--untracked-files=all", "--", PACK_REL)
        local_only = [l for l in st.splitlines() if l[:2] in ("??", "!!") and "__pycache__" not in l]
        res["source_checkout_untracked_or_ignored"] = [l[3:] for l in local_only]
        res["checks"]["no_local_only_files"] = not local_only

        venv = os.path.join(tmp, "venv")
        subprocess.run([sys.executable, "-m", "venv", venv], check=True)
        py = os.path.join(venv, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv, "bin", "python")
        subprocess.run([py, "-m", "pip", "install", "-q", "--disable-pip-version-check", "-r",
                        os.path.join(pack, "requirements.txt")], check=True)
        res["venv_packages"] = subprocess.run([py, "-m", "pip", "freeze", "--all"], capture_output=True,
                                              text=True).stdout.split()
        home = os.path.join(tmp, "home")
        ttmp = os.path.join(tmp, "tmp")
        os.makedirs(home)
        os.makedirs(ttmp)
        env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "COMSPEC", "LANG") if k in os.environ}
        env.update({"HOME": home, "USERPROFILE": home, "APPDATA": home, "LOCALAPPDATA": home,
                    "TEMP": ttmp, "TMP": ttmp, "TMPDIR": ttmp})
        inner_out = os.path.join(ttmp, "inner.json")
        r = subprocess.run([py, "-E", "-s", "-B", os.path.join(pack, "tests", "repro", "check_clean_checkout.py"),
                            "--inner", "--forbid", src_top, "--out", inner_out], cwd=pack, env=env)
        inner = json.load(open(inner_out, encoding="utf-8")) if os.path.exists(inner_out) else {"verdict": "ERROR"}
        res["inner_rc"] = r.returncode
        res["inner"] = inner
        res["checks"].update(inner.get("checks", {}))
        res["checks"]["inner_completed"] = r.returncode in (0, 1) and "checks" in inner
        res["checks"]["home_untouched"] = not os.listdir(home)
        dirty = git(clone, "status", "--porcelain", "--ignored", "--untracked-files=all", "--", PACK_REL)
        res["clone_changes_after_run"] = dirty.splitlines()
        res["checks"]["clone_unchanged"] = not dirty
    finally:
        if a.keep:
            res["kept_tmp"] = tmp
        else:
            remove_tree(tmp)
            res["checks"]["temp_dir_removed"] = not os.path.exists(tmp)
    res["verdict"] = "PASS" if res["checks"] and all(res["checks"].values()) else "FAIL"
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "clean_checkout.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)
        fh.write("\n")
    print("tested commit", sha)
    for k, v in res.get("revisions", {}).items():
        print("  %-18s %s" % (k, v))
    for m in res["inner"].get("monitors", []):
        print("  %-44s %s identical=%s" % (m["file"], m["content_hash"], m["identical"]))
    for k, v in res["checks"].items():
        print("  [%s] %s" % ("PASS" if v else "FAIL", k))
    print(res["verdict"])
    return 0 if res["verdict"] == "PASS" else 1


# --------------------------------------------------------------------------------------- inner
def inner(a):
    pack = os.path.realpath(os.getcwd())
    clone = os.path.realpath(os.path.join(pack, "..", ".."))
    rel = lambda p: os.path.relpath(p, clone).replace(os.sep, "/") if inside(p, clone) else "<outside clone>"  # noqa: E731
    res = {"python": sys.version.split()[0], "platform": platform.platform(), "checks": {}}
    res["checks"]["sys_path_clean"] = not any(p and inside(p, a.forbid) for p in sys.path)
    import yaml
    res["pyyaml"] = yaml.__version__

    buf = io.StringIO()
    r = unittest.TextTestRunner(stream=buf, verbosity=2).run(
        unittest.TestLoader().discover(os.path.join(pack, "tests", "unit")))
    res["unit"] = {"run": r.testsRun, "failures": len(r.failures), "errors": len(r.errors),
                   "skipped": len(r.skipped), "output": buf.getvalue().splitlines()}
    res["checks"]["unit_tests_pass"] = r.wasSuccessful() and r.testsRun > 0
    mods = {n: getattr(m, "__file__", None) for n, m in list(sys.modules.items())
            if n == "wcp" or n.startswith(("wcp.", "test_"))}
    res["module_origins"] = {n: rel(f) for n, f in sorted(mods.items()) if f}
    res["checks"]["modules_from_clone"] = bool(mods) and all(f and inside(f, clone) for f in mods.values())
    res["checks"]["nothing_from_source_checkout"] = not any(
        inside(getattr(m, "__file__", None), a.forbid) for m in list(sys.modules.values())
        if getattr(m, "__file__", None))

    cli = [sys.executable, "-E", "-s", "-B"]
    origin = subprocess.run(cli + ["-c", "import os, wcp; print(os.path.realpath(wcp.__file__))"], cwd=pack,
                            capture_output=True, text=True).stdout.strip()
    res["cli_wcp_origin"] = rel(origin) if origin else None
    res["checks"]["cli_imports_clone"] = bool(origin) and inside(origin, clone)
    v = subprocess.run(cli + ["-m", "wcp", "validate"], cwd=pack, capture_output=True, text=True)
    res["validate"] = {"rc": v.returncode, "output": (v.stdout + v.stderr).splitlines()}
    res["checks"]["validate_ok"] = v.returncode == 0

    # offline self-tests of the RC2 validation harness (tests/validation/, added after 38ad481), in
    # their own process; they read no lab configuration (none exists in this environment)
    vdir = os.path.join(pack, "tests", "validation")
    if os.path.isdir(vdir):
        st = subprocess.run(cli + ["-m", "unittest", "discover", "-s", "tests/validation", "-p", "test_*.py"],
                            cwd=pack, capture_output=True, text=True)
        out = (st.stdout + st.stderr).splitlines()
        ran = [l for l in out if l.startswith("Ran ")]
        res["validation_selftests"] = {"rc": st.returncode, "summary": ran + out[-1:], "output_tail": out[-15:]}
        res["checks"]["validation_selftests_pass"] = st.returncode == 0 and bool(ran) and out[-1].startswith("OK")
        o = subprocess.run(cli + ["-c", "import os, sys; sys.path.insert(0, 'tests/validation'); import vlib; "
                                  "print(os.path.realpath(vlib.__file__)); print(os.path.realpath(vlib.A.__file__))"],
                           cwd=pack, capture_output=True, text=True).stdout.split("\n")
        o = [x.strip() for x in o if x.strip()]
        res["validation_origins"] = [rel(x) for x in o]
        res["checks"]["validation_imports_clone"] = len(o) == 2 and all(inside(x, clone) for x in o)

    sys.path.insert(0, pack)
    from wcp import alerting as A
    exp = os.path.join(pack, "expected", "monitors")
    with tempfile.TemporaryDirectory() as td:
        rr = subprocess.run(cli + ["-m", "wcp", "render", "--out", td], cwd=pack, capture_output=True, text=True)
        got = sorted(os.listdir(td))
        want = sorted(f for f in os.listdir(exp) if f.endswith(".monitor.json"))
        mons = []
        # Line endings depend on the platform and git's core.autocrlf (render writes text mode,
        # a checkout may convert LF to CRLF): compare and hash with LF line endings, which is the
        # committed form, so the result and the hashes are the same on every platform.
        lf = lambda b: b.replace(b"\r\n", b"\n") if b is not None else None  # noqa: E731
        for f in sorted(set(got) | set(want)):
            x = open(os.path.join(td, f), "rb").read() if f in got else None
            y = open(os.path.join(exp, f), "rb").read() if f in want else None
            body = json.loads(y.decode("utf-8")) if y else {}
            mons.append({"file": f, "identical": x is not None and lf(x) == lf(y),
                         "content_hash": A.content_hash(body) if body else None,
                         "marker_content_hash": A.marker_of(body).get("content_hash"),
                         "sha256_lf": hashlib.sha256(lf(y)).hexdigest() if y else None,
                         "checkout_eol": ("crlf" if b"\r\n" in y else "lf") if y else None,
                         "render_eol": ("crlf" if b"\r\n" in x else "lf") if x else None})
    res["monitors"] = mons
    res["checks"]["rendered_equal_expected"] = (rr.returncode == 0 and got == want and bool(want)
                                                and all(m["identical"] for m in mons))
    res["checks"]["marker_hash_matches_content"] = all(m["content_hash"] == m["marker_content_hash"] for m in mons)

    bad, n = [], 0
    for d, _s, fs in os.walk(pack):
        for f in fs:
            if f.endswith(".py"):
                n += 1
                p = os.path.join(d, f)
                try:
                    compile(open(p, encoding="utf-8").read(), p, "exec")
                except SyntaxError as e:
                    bad.append("%s: %s" % (rel(p), e))
    res["compile"] = {"files": n, "errors": bad}
    res["checks"]["all_python_compiles"] = not bad

    tracked = set(subprocess.run(["git", "ls-files"], cwd=pack, capture_output=True, text=True).stdout.split())
    dirs = set()
    for t in tracked:
        while t:
            t = os.path.dirname(t)
            dirs.add(t)
    missing = []
    for md in sorted(t for t in tracked if t.endswith(".md")):
        for m in DOC_REF.finditer(open(os.path.join(pack, md), encoding="utf-8").read()):
            ref = m.group(1).rstrip("/.")
            cands = {os.path.normpath(os.path.join(os.path.dirname(md), ref)).replace(os.sep, "/"),
                     os.path.normpath(ref).replace(os.sep, "/")}
            if "<" not in ref and "*" not in ref and not (cands & (tracked | dirs)):
                missing.append("%s -> %s" % (md, ref))
    res["doc_references_unresolved"] = sorted(set(missing))
    res["checks"]["doc_references_resolve"] = not missing

    res["verdict"] = "PASS" if all(res["checks"].values()) else "FAIL"
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)
    return 0 if res["verdict"] == "PASS" else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--commit", default="HEAD")
    ap.add_argument("--repo", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--out", required=True)
    ap.add_argument("--keep", action="store_true", help="keep the temporary clone and venv")
    ap.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--forbid", help=argparse.SUPPRESS)
    a = ap.parse_args()
    return inner(a) if a.inner else outer(a)


if __name__ == "__main__":
    raise SystemExit(main())
