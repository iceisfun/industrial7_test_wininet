# wininet.dll conformance corpus

Black-box tests for Windows 10 x64 `wininet.dll`. The DLL is never linked: each test loads it with `LoadLibrary`,
resolves entry points with `GetProcAddress` (`U(Name)` gives a pointer typed from the SDK header;
`UIN("module.dll", Name)` pins one module, which matters for forwarders) and calls through the pointer.

Modules searched by `U()`: wininet.dll urlmon.dll winhttp.dll sspicli.dll schannel.dll crypt32.dll ws2_32.dll ntdll.dll kernel32.dll.

    make                         # cross-compile build/<area>.exe (mingw-w64)
    build\<area>.exe [substr]    # on Windows; optional test-name filter
    tools\run_all.bat            # everything, results\<area>.txt (add /destructive for dx_* areas)
    python tools\summarize.py results [--failures]

Output: `RUN/OK/FAIL/SKIP` per test, `  FAIL file:line expr (detail)` per failed check, `SUMMARY` last;
exit code 1 if any test failed. `NOTE` lines record observed, version-dependent behaviour.

Tests that need a second process re-launch the exe (`--child <name>`). Scratch files live in
`%TEMP%\wininet_<pid>\` and are removed on exit. `tools/*_exports.txt` list the named exports.

See `HANDOFF.md` (when present) for how to run and triage the Windows passes.

## Network tests and the Windows 10 VM
- `common/srv.h` (+ `common/SRV.md`): in-process loopback HTTP/HTTPS(schannel)/FTP servers with a wire recorder;
  `common/tnet.h`: DIRECT sessions with timeouts, unique cache/cookie names, cleanup registries. No test uses the internet.
- `tools/vm_run.sh AREA[,AREA]` / `tools/vm_run.sh --all` / `tools/vm_matrix.sh [--twice]`: run on the local Win10 22H2
  VM, results in `results/win10/<area>.txt` (see `docs/VM_RUN.md`). The VM is the oracle; Wine is plumbing only.
- `tests/net_loopback`: proof area for the chain (HTTP, HTTPS, FTP, auth, decoding) validated on the VM.
