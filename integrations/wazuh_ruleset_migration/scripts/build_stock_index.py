#!/usr/bin/env python3
"""Write the index of a 4.x stock ruleset to a file, to inspect it.

Usage::

    python3 scripts/build_stock_index.py --stock-dir <4.x ruleset/ directory> --out <file> [--source LABEL]

``migrate`` builds the same index at run time and caches it in the working
directory (``work/stock-index.json``). The output is deterministic: running it
twice on the same tree gives the same bytes. No network access.
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from rmig import stock  # noqa: E402
from rmig.jsonio import write_text  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--stock-dir", required=True, help="the 4.x ruleset/ directory, or a directory that holds it")
    ap.add_argument("--source", default=stock.STOCK_LABEL, help="provenance label written in the index")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    if stock.ruleset_dir(args.stock_dir) is None:
        print("error: %s has no rules/ and decoders/" % args.stock_dir, file=sys.stderr)
        return 2
    index = stock.build_index(args.stock_dir, args.source)
    write_text(args.out, stock.dump_index(index))
    c = index["counts"]
    print("rules %d in %d files; decoders %d in %d files; lists %d -> %s" % (
        c["rules"], c["rule_files"], c["decoders"], c["decoder_files"], c["lists"], args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
