# Running the corpus on the local Windows 10 VM

The oracle for this corpus is genuine Windows 10 22H2 (`ver` 10.0.19045.2965, wininet.dll 11.0.19041.2193). It runs as a
throw-away QEMU/KVM guest on the dev host. Wine is not an oracle for wininet: use it only to check that the plumbing works.

## One-time facts
- Lab: `~/w10lab` (see `~/w10lab/README.md`). The base disk comes from `bb depot get m2`, giving `~/w10lab/win10base.qcow2`. Every run
  boots a fresh qcow2 overlay, so nothing persists between boots.
- `~/w10lab/LAB_READY` exists once the lab owner has validated a smoke boot. `tools/vm_run.sh` waits for it, polling for up to 40 min.
- **One guest at a time** on this host, across all workflows. `~/w10lab/tools/win10_run.sh` takes `~/w10lab/oracle.lock`
  and blocks until it is free. Never start qemu any other way.
- The guest has no internet (`-nic user,restrict=on`). Firewall and Defender are as installed. Neither interferes with
  loopback servers (04 F1).
- Results return over COM1. The guest hook runs `D:\i7run\run.cmd` at logon and powers off when it returns.

## Commands
```
make                                         # build/<area>.exe + build/tools/vmrun.exe
tools/vm_run.sh net_loopback                 # one area (names or build/x.exe paths, comma or space separated)
tools/vm_run.sh core_smoke,net_loopback --filter netlb_https
tools/vm_run.sh --all                        # every non-dx area (dx_* need --destructive)
tools/vm_matrix.sh                           # build + --all + summarize.py --failures
tools/vm_matrix.sh --twice                   # two independent boots + per-test flakiness comparison
python3 tools/summarize.py results/win10 --failures
```
Results:
- `results/win10/<area>.txt` has the area's stdout exactly as on Windows, plus a final `@@I7 END ...` line from the runner.
- `results/win10/_vm_status.log` has one status line per area.
- The boot dirs, holding `serial.log`, the payload and `payload.iso`, are in `~/w10lab/runs/wininet-<stamp>-b<n>/`.
- Exit code: 0 only if every area is PASS.

Options of `vm_run.sh`:

| Option | Effect |
|---|---|
| `--filter S` | test-name substring, passed as argv[1] to each exe |
| `--timeout N` | per-exe seconds. By default each area uses the largest `VM_TIMEOUT: N` comment in `tests/<area>/*.c`, else 120 |
| `--out DIR` | results directory |
| `--runs DIR` | where the boot dirs go |
| `--tag T` | boot dir name prefix |
| `--no-build` | skip `make` |
| `--extra FILE` | copy FILE into the payload as well |
| `--destructive` | include `dx_*` areas |

## How it works
1. **Payload.** `vm_run.sh` stages the exes, `build/tools/vmrun.exe` and a generated `run.cmd` into
   `<bootdir>/payload`. The `run.cmd` echoes a `@@I7 RUNSTART` marker and `ver`, then runs one
   `vmrun.exe -t <secs> -n <area> -- <area>.exe [filter]` line per exe, then echoes `@@I7 RUNEND`. Nothing else writes COM1
   while vmrun runs: COM1 is exclusive, and a second writer loses its output silently (04 F16).
2. **Runner.** `vmrun.exe` (source `tools/vmrun.c`) opens COM1 once. It starts the exe suspended in a kill-on-close job
   (`DIE_ON_UNHANDLED_EXCEPTION`, no GP fault dialog, stdin=NUL), pumps stdout and stderr to COM1, and frames the run:
   ```
   @@I7 BEGIN <area> "<area>.exe" [args]
   ...exe output...
   @@I7 END <area> exit=0x<code> ms=<n> timeout=<0|1> bytes=<n>
   ```
   On a timeout the whole job tree is killed (`exit=0xdead0001 timeout=1`). A crash shows up as its NTSTATUS
   (for example `exit=0xc0000005`), with no WER stall.
3. **Boot packing.** Areas are packed into as few boots as possible. `ORACLE_TIMEOUT` is the sum of the per-exe timeouts plus 150 s for boot
   and drain, capped at 900 s. When an area list does not fit, it is split into several boots, which queue on the lock.
   A boot costs about 40 s before the first COM1 byte, plus test time, plus about 4 s per MB of output (04 F15).
4. **Split and validate.** `tools/vm_split.py serial.log results/win10 --expect a,b` writes one file per frame and
   classifies each area:

   | Status | Meaning |
   |---|---|
   | PASS | END present, exit 0, `SUMMARY ... failed=0` |
   | FAIL | `failed>0` or exit 1 |
   | TIMEOUT | vmrun killed the area. Never counts as a pass |
   | CRASHED | END but no SUMMARY, or an exit code other than 0/1 |
   | TRUNCATED | BEGIN without END (guest died or ORACLE_TIMEOUT), or fewer bytes captured than vmrun forwarded |
   | MISSING | an expected area never started |

## Writing tests that behave on the VM
- **Scratch and state.** The payload ISO is read-only. Tests write under `%TEMP%` (`t_tmpdir()`). The overlay is discarded after every
  boot, but tests must still clean up, because other lanes re-run the corpus on persistent Windows boxes.
- **Clock.** The guest clock is about 1 h behind the host (RTC = localtime, guest TZ PST, F14). Compute every time inside the
  guest (`GetSystemTime`), and use day-sized margins for expiry.
- **Waits and UI.** Keep waits bounded at a few seconds. Never block on UI: always `INTERNET_FLAG_NO_UI`, and no `InternetErrorDlg` without
  `FLAGS_ERROR_UI_FLAGS_NO_UI`.
- **Promoting a check.** A new hard CHECK must pass on the VM. Anything that differs between two boots (`vm_matrix.sh --twice`) is a
  `t_note`, not a CHECK.
- **Registry state.** Record what the image has (proxy settings, `SecureProtocols=0x800`, revocation) with `t_note`; `tnet.h`'s
  `t_net_prepare()` prints one line per exe. Change it only in `dx_*` areas, and restore it afterwards.

## Troubleshooting
- **`waiting for oracle lock...` for a long time.** Another workflow's guest is running. `pgrep -af qemu-system` shows it.
- **TRUNCATED with no BEGIN at all.** Look at the boot's `serial.log`. The hook prints `I7VM: logon` and `I7VM: payload D:\i7run`.
  If those lines are missing, the guest did not boot or log on. `W10_VNC=<n>` exposes the guest display on 127.0.0.1:59xx.
- **An area hangs.** vmrun kills it at its timeout and the rest of the boot continues. Raise `VM_TIMEOUT:` only if the area
  is legitimately slow, and keep every area under a few minutes.
- **Reproducing by hand.** `~/w10lab/tools/win10_run.sh <bootdir>/payload /tmp/somewhere` re-runs the exact payload.
