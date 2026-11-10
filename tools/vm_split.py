#!/usr/bin/env python3
"""Split a Win10 VM serial.log (framed by tools/vmrun.exe) into <outdir>/<area>.txt and validate each area.

usage: vm_split.py SERIAL_LOG OUTDIR [--expect a,b,c] [--quiet]

Frames written by vmrun.exe:
    @@I7 BEGIN <name> <cmdline>
    ...child stdout/stderr verbatim...
    \r\n@@I7 END <name> exit=0x<code> ms=<n> timeout=<0|1> bytes=<n>

Status per area (exit code 1 if any area is not PASS):
    PASS       END present, exit=0, SUMMARY present with failed=0
    FAIL       SUMMARY failed>0 (or exit=1)
    TIMEOUT    vmrun killed it at the deadline (timeout=1): never a pass
    CRASHED    END present but no SUMMARY line, or an exit code other than 0/1 (exception, 0xDEAD0000 spawn failure)
    TRUNCATED  BEGIN without END (guest died / ORACLE_TIMEOUT), or fewer bytes captured than vmrun forwarded
    MISSING    expected area never started (no BEGIN)
"""
import os, re, sys

def main():
    a = sys.argv[1:]
    if len(a) < 2:
        print(__doc__); return 2
    log, out = a[0], a[1]
    expect = []
    if "--expect" in a:
        expect = [x for x in a[a.index("--expect") + 1].split(",") if x]
    quiet = "--quiet" in a
    data = open(log, "rb").read()
    os.makedirs(out, exist_ok=True)
    begin_re = re.compile(rb"@@I7 BEGIN (\S+)[^\n]*\n")
    end_re = re.compile(rb"\r?\n?@@I7 END (\S+) exit=(0x[0-9a-fA-F]+) ms=(\d+) timeout=(\d) bytes=(\d+)[^\n]*\n?")
    results = {}
    pos = 0
    while True:
        m = begin_re.search(data, pos)
        if not m: break
        name = m.group(1).decode(errors="replace")
        body_start = m.end()
        e = end_re.search(data, body_start)
        nb = begin_re.search(data, body_start)
        if e and (not nb or e.start() <= nb.start()) and e.group(1).decode(errors="replace") == name:
            body = data[body_start:e.start()]
            code = int(e.group(2), 16); ms = int(e.group(3)); tmo = e.group(4) == b"1"; nbytes = int(e.group(5))
            end_line = e.group(0).strip().decode(errors="replace")
            pos = e.end()
        else:
            stop = nb.start() if nb else len(data)
            body = data[body_start:stop]; code = None; ms = None; tmo = False; nbytes = None; end_line = None
            pos = stop
        text = body.decode("utf-8", errors="replace").replace("\r\n", "\n")
        with open(os.path.join(out, name + ".txt"), "w", newline="\n") as f:
            f.write(text)
            if text and not text.endswith("\n"): f.write("\n")
            f.write((end_line or "@@I7 END missing (TRUNCATED)") + "\n")
        summ = re.findall(r"SUMMARY tests=(\d+) failed=(\d+) skipped=(\d+) checks_pass=(\d+) checks_fail=(\d+)", text)
        if code is None:
            st, why = "TRUNCATED", "no END frame"
        elif tmo:
            st, why = "TIMEOUT", "killed after %d ms" % ms
        elif nbytes is not None and len(body) < nbytes:
            st, why = "TRUNCATED", "captured %d of %d bytes" % (len(body), nbytes)
        elif not summ:
            st, why = "CRASHED", "no SUMMARY (exit=0x%x)" % code
        elif code not in (0, 1):
            st, why = "CRASHED", "exit=0x%x" % code
        else:
            t, fl, sk, cp, cf = map(int, summ[-1])
            st = "FAIL" if fl or code == 1 else "PASS"
            why = "tests=%d failed=%d skipped=%d checks_fail=%d ms=%d" % (t, fl, sk, cf, ms)
        results[name] = (st, why)
    for n in expect:
        if n not in results:
            results[n] = ("MISSING", "no BEGIN frame")
            with open(os.path.join(out, n + ".txt"), "w") as f:
                f.write("@@I7 MISSING: %s never started in %s\n" % (n, log))
    bad = 0
    lines = []
    for n in sorted(results):
        st, why = results[n]
        if st != "PASS": bad += 1
        lines.append("%-40s %-9s %s" % (n, st, why))
    lines.append("VM_SPLIT areas=%d not_pass=%d log=%s" % (len(results), bad, log))
    with open(os.path.join(out, "_vm_status.log"), "a") as f:
        f.write("\n".join(lines) + "\n")
    if not quiet:
        print("\n".join(lines))
    return 1 if bad or not results else 0

if __name__ == "__main__":
    sys.exit(main())
