#!/usr/bin/env python3
"""Fail if a shipping binary contains the conformance-test hooks.

docs/PROTOCOL.md Appendix A: shipping builds MUST NOT contain the selftest
hooks. This looks for the hook flags in UTF-8 and UTF-16LE (Windows wide
strings).

Usage: python tests/check_no_selftest.py <binary> [<binary> ...]
"""

import sys

MARKERS = [
    "--selftest-server",
    "--selftest-client",
    "--selftest-pair-server",
    "--selftest-pair-client",
    "--selftest-discover",
    "--selftest-verify-update",
    "--preview",  # Windows UI preview build (KEYBRIDGE_UI_PREVIEW) only
]


def main(paths):
    if not paths:
        sys.exit(__doc__)
    bad = False
    for path in paths:
        with open(path, "rb") as f:
            data = f.read()
        found = [m for m in MARKERS if m.encode("utf-8") in data or m.encode("utf-16-le") in data]
        if found:
            bad = True
            print(f"FAIL {path}: contains selftest hook(s) {', '.join(found)}")
        else:
            print(f"ok   {path}: no selftest hooks ({len(data)} bytes)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
