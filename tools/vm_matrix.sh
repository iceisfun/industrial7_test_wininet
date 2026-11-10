#!/usr/bin/env bash
# Run the whole corpus on the local Win10 VM and summarise. See docs/VM_RUN.md.
#   tools/vm_matrix.sh [--twice] [--destructive] [vm_run.sh options...]
# --twice: two independent boots (results/win10 and results/win10_b) and a per-test comparison; a test whose
#          outcome differs between boots is FLAKY and must not carry hard CHECKs (04 section 3).
# Exit code: non-zero if any area is not PASS (or, with --twice, any test is flaky).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
TWICE=0; ARGS=()
for a in "$@"; do [ "$a" = "--twice" ] && TWICE=1 || ARGS+=("$a"); done
make -s all || exit 2
rc=0
tools/vm_run.sh --all --no-build --out results/win10 "${ARGS[@]}" || rc=1
python3 tools/summarize.py results/win10 --failures
if [ "$TWICE" = 1 ]; then
  tools/vm_run.sh --all --no-build --out results/win10_b --tag wininet-b "${ARGS[@]}" || rc=1
  python3 - "$ROOT/results/win10" "$ROOT/results/win10_b" <<'EOF' || rc=1
import glob, os, re, sys
def outcomes(d):
    r = {}
    for f in glob.glob(os.path.join(d, "*.txt")):
        for line in open(f, errors="replace"):
            m = re.match(r"^(OK  |FAIL|SKIP) (\S+)$", line.rstrip("\n"))
            if m: r[(os.path.basename(f), m.group(2))] = m.group(1).strip()
    return r
a, b = outcomes(sys.argv[1]), outcomes(sys.argv[2])
flaky = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
for k in flaky: print("FLAKY %s %s: %s vs %s" % (k[0], k[1], a.get(k), b.get(k)))
print("vm_matrix: %d tests compared, %d flaky" % (len(set(a) | set(b)), len(flaky)))
sys.exit(1 if flaky else 0)
EOF
fi
exit $rc
