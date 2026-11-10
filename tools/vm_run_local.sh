#!/usr/bin/env bash
# Run corpus exes on LOCAL Win10 22H2 guests (scripts/win10vm/win10vm.sh from the industrial7 repo), one boot per area,
# several boots in parallel. Results: results/win10/<area>.txt (vm_split.py), boot dirs under $W10_I7ROOT/target/win10vm/runs.
#   W10_I7ROOT=<dir with scripts/win10vm and target/win10vm/base.qcow2 (bb depot get m2)>  PAR=6  tools/vm_run_local.sh [area ...|--all]
# xorriso is needed by win10vm.sh (a pycdlib shim works). Guests have no network; loopback servers are in-guest.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; I7="${W10_I7ROOT:?set W10_I7ROOT}"; PAR="${PAR:-6}"; OUT="${OUT:-$ROOT/results/win10}"
TAG="${TAG:-wl-$(date +%H%M%S)}"; cd "$ROOT"
[ "${1:-}" = "--all" ] || [ $# -eq 0 ] && set -- $(ls tests | grep -v '^dx_')
mkdir -p "$OUT"
one() {
  n="$1"; exe="$ROOT/build/$n.exe"; [ -f "$exe" ] || { echo "$n: no exe"; return 2; }
  t="$(grep -ho 'VM_TIMEOUT: *[0-9]\+' "$ROOT/tests/$n"/*.c 2>/dev/null | grep -o '[0-9]\+' | sort -n | tail -1)"; t="${t:-120}"
  id="$TAG-$n"; pay="$I7/target/win10vm/pay/$id"; rm -rf "$pay"; mkdir -p "$pay"
  cp "$ROOT/build/tools/vmrun.exe" "$exe" "$pay/"
  { echo "@echo off"; echo "mode COM1:115200,n,8,1 >nul"; echo "cd /d %~dp0"
    echo "echo @@I7 RUNSTART $id %date% %time% > COM1"; echo "ver > COM1"
    echo "vmrun.exe -t $t -n $n -- $n.exe"; echo "echo @@I7 RUNEND $id %date% %time% > COM1"; } > "$pay/run.cmd"
  ( cd "$I7" && I7_ROOT="$I7" WIN10_VNC=none bash scripts/win10vm/win10vm.sh run --payload "$pay" --shutdown --timeout $((t + 240)) --id "$id" </dev/null >"$I7/target/win10vm/$id.log" 2>&1 )
  log="$I7/target/win10vm/runs/$id/serial.log"
  python3 "$ROOT/tools/vm_split.py" "$log" "$OUT" --expect "$n" --quiet >>"$OUT/_vm_status.log" 2>&1 || true
  echo "$n done (budget ${t}s) -> $log"
}
export -f one; export ROOT I7 OUT TAG
printf '%s\n' "$@" | xargs -P "$PAR" -I{} bash -c 'one {}'
