#!/usr/bin/env python3
"""Freeze Win10-observed signatures into the table rows of this area.

    python3 tests/http_edge_protocol/fill_sigs.py results/win10/http_edge_protocol.txt [--dry-run]

Reads the "NOTE OBS <tag> | <signature>" lines that hep_expect_sig() prints for rows whose expectation is NULL, and
rewrites the matching RCASE/RCASEH/RCASECL(<tag>, ..., NULL) and EXPECT_SIG("<tag>", ..., NULL) rows in the .c files
of this directory with the observed signature as the expectation. Only rows still at NULL are touched; rows listed
in SKIP (variable between boots, see EVIDENCE.md) are left as observations.
"""
import re, sys, pathlib

SKIP = set()

def c_lit(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'

def main():
    res = pathlib.Path(sys.argv[1]).read_text(errors='replace')
    dry = '--dry-run' in sys.argv
    obs = {}
    for m in re.finditer(r'^  NOTE OBS (\S.*?) \| (.*)$', res, re.M):
        obs.setdefault(m.group(1), m.group(2))
    here = pathlib.Path(__file__).parent
    n = 0
    for f in sorted(here.glob('*.c')):
        src = f.read_text()
        out = src
        for tag, sig in obs.items():
            if tag in SKIP:
                continue
            # table rows: RCASE*(tag, ...., NULL) at line end
            pat = re.compile(r'^(RCASE(?:H|CL)?\(' + re.escape(tag) + r',.*), NULL\)$', re.M)
            out, k = pat.subn(lambda mm: mm.group(1) + ', ' + c_lit(sig) + ')', out)
            n += k
            # any call on one line: fn("tag", ..., NULL ...) -> first NULL after the tag
            pat2 = re.compile(r'(\b\w+\(' + re.escape(c_lit(tag)) + r', [^;\n]*?)\bNULL\b')
            out, k = pat2.subn(lambda mm: mm.group(1) + c_lit(sig), out, count=1)
            n += k
        if out != src and not dry:
            f.write_text(out)
    print(f'{len(obs)} observations, {n} rows frozen')

if __name__ == '__main__':
    main()
