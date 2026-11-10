# 04 - Loopback test servers and the Win10 VM loop

This doc does two things. It specifies the in-process server library that wininet tests talk to
(`common/srv.*`, built by the foundation role), and the way the corpus runs on the local Windows 10 VM.
Every number below was measured on that VM: Windows 10 22H2, `ver` 10.0.19045.2965, wininet.dll
11.0.19041.2193. It ran on 2026-11-09 under `~/w10lab/tools/win10_run.sh`.

- Prototypes: `tools/proto/proto.c` (probes), `tools/proto/vmrun.c` (guest runner), payloads `run.cmd` / `run2.cmd`,
  `build.sh`.
- Raw evidence: `tools/proto/evidence/round1.serial.txt` and `round2.serial.txt`. These are the guest COM1 logs with the bulk
  spew lines removed. Unfiltered copies are in `~/w10lab/runs/wininet-proto{1,2}/serial.log`.
- Each `P <key> ...` line cited below is in those files.

## 0. Findings that change how tests are written

| # | Finding (Win10 VM) | Evidence | Consequence |
|---|---|---|---|
| F1 | Loopback TCP works over IPv4 and IPv6 in the guest. Firewall is ON for all three profiles and Defender (WinDefend) is running, yet neither interferes with 127.0.0.1/::1 servers: no prompt and no delay. | `loop4`, `loop6`, `netsh advfirewall` block | Bind loopback only. Never bind 0.0.0.0, because that can raise the firewall "allow access" UI. |
| F2 | `localhost` resolves to **`::1` first, then 127.0.0.1**. On Windows a refused loopback connect takes about **2 s** (SYN retries after RST). The result is that wininet to `http://localhost:P/` against a v4-only server takes **2031-2044 ms**. Against a server listening on both `::1` and 127.0.0.1 on the same port it takes **0.7 ms**. | `http_direct_localhost` 2043.9 ms; `localhost_v4only` 2031.4; `localhost_dualstack` 0.7; `refused_raw4/6` 2036/2062 ms | The server library **listens on 127.0.0.1 and [::1] with the same port** by default. URLs default to the `127.0.0.1` literal. |
| F3 | Connection-refused negative tests are slow: wininet returns `ERROR_INTERNET_CANNOT_CONNECT` (12029) after **2010 ms** for 127.0.0.1 and **4093 ms** for `localhost` (two addresses). | `refused_wininet_*` | At most a few refused-connect tests per area. Always use the IP literal. Budget 2 s for each. |
| F4 | No WPAD delay. Per-connection flags are 0x9 (DIRECT \| AUTO_DETECT): auto-detect is on. Even so, `INTERNET_OPEN_TYPE_PRECONFIG` costs the same as DIRECT (1.3 ms against 1.2 ms). `WinHttpDetectAutoProxyConfigUrl` fails with 12180 (`ERROR_WINHTTP_AUTODETECTION_FAILED`) in **0.4 ms**, and NXDOMAIN fails with 12007 in 0.5 ms (DIRECT) or 2.4 ms (PRECONFIG). Loopback is bypassed implicitly: the decomp has `PROXY_BYPASS_LIST` honour the `<-loopback>` macro (`IsLoopbackMacro`). | `perconn`, `ieproxy`, `wpad_detect`, `http_preconfig_*`, `http_*_nxdomain` | Use `INTERNET_OPEN_TYPE_DIRECT` everywhere except in proxy tests. PRECONFIG is cheap in this guest, but a different network (DHCP option 252, a DNS suffix) could make autodetect slow. DIRECT also keeps results independent of proxy config. |
| F5 | The guest has no DNS: every name except `localhost` fails at once (getaddrinfo 11001 in 0.3 ms). | `resolve` | Tests that need a non-loopback host name must expect 12007 and nothing else. Do not invent "resolves to X" tests. |
| F6 | `HKCU\...\Internet Settings`: `SecureProtocols=0x800` (**TLS 1.2 only** for wininet), `CertificateRevocation=1`, `EnableNegotiate=1`, `ProxyEnable=0`, `User Agent` = `Mozilla/4.0 (compatible; MSIE 8.0; Win32)`. | `reg query` block in round 1 | TLS 1.0/1.1 client tests fail by default on this image. They need a dx_ area that sets the option per session (`INTERNET_OPTION_SECURE_PROTOCOLS`) or must be skipped. Revocation is on, but a self-signed leaf without a CDP passes (F8). |
| F7 | The schannel **server** works headless as Administrator. `CertCreateSelfSignCertificate` (sha256RSA, 2048-bit key) takes 0.6-18 ms. `AcquireCredentialsHandle(UNISP_NAME, SECPKG_CRED_INBOUND)` returns `SEC_E_OK` with a **CAPI key** (MS_ENH_RSA_AES_PROV, AT_KEYEXCHANGE) and with a **CNG key** (MS_KEY_STORAGE_PROVIDER), under both `SCHANNEL_CRED` v4 and `SCH_CREDENTIALS` v5. The negotiated session is TLS 1.2 (server 0x400 / client 0x800), cipher suite **0xC030** (ECDHE_RSA_AES_256_GCM_SHA384), aiCipher 0x6610. | `selfsign`, `acquire_inbound`, `*_srv_tls`, `cache_s1_ignoreca` | Default to a CNG key, which is faster: 0.6 ms against 18 ms for the first CAPI key. Delete the key container afterwards (`NCryptDeleteKey`, checked rc=0). |
| F8 | wininet against a self-signed `CN=localhost` cert, observed one step at a time on a single request handle:<br>- `https://127.0.0.1` with **no SAN** fails with **12045** `ERROR_INTERNET_INVALID_CA`.<br>- Adding `SECURITY_FLAG_IGNORE_UNKNOWN_CA` (0x100) gives **12038** `ERROR_INTERNET_SEC_CERT_CN_INVALID`.<br>- Then adding `IGNORE_CERT_CN_INVALID` (0x1000) gives 200.<br>- `https://localhost` needs only 0x100.<br>- With **SAN = DNS:localhost + IP:127.0.0.1**, the 127.0.0.1 host also needs only 0x100: the SSL policy matches the IP SAN.<br>After success, `INTERNET_OPTION_SECURITY_FLAGS` reads `0x20000101` = STRENGTH_STRONG \| IGNORE_UNKNOWN_CA \| SECURE, or `0x20001101` when CN was also ignored. The request flag `INTERNET_FLAG_IGNORE_CERT_CN_INVALID` shows up as security flag 0x1000. | `https_cng0_san0_ip`, `https_cng1_san1_*`, `openflag_*` | The default server cert is `CN=localhost` with SAN {DNS:localhost, IP:127.0.0.1, IP:::1} and EKU serverAuth. A test then needs exactly one flag (0x100) on either name. Tests that target the CN-mismatch path use a second cert profile (`SRV_CERT_CN_OTHER`). |
| F9 | Ignore flags are **not remembered** across requests or sessions. On the same host and port, a new request without flags fails with 12045 again, even right after a successful ignored request in the same session, and in a new `InternetOpen` session too. `INTERNET_OPTION_SECURITY_FLAGS` on the **session** handle fails with **12018** (`ERROR_INTERNET_INCORRECT_HANDLE_TYPE`). | `cache_s1_again_noflags`, `cache_s2_*`, `sessionflags set ok=0 err=12018` | Every HTTPS request must set the flag itself. Sharing a port between tests does not make results depend on test order for cert errors. The decomp does have a per-host `SECURITY_CACHE_LIST` (`HandleCachedServerCert`), so a fresh port per test is still the default. |
| F10 | `INTERNET_OPTION_SECURITY_CONNECTION_INFO` (66) needs the **full** struct: dwSize, fSecure, SecPkgContext_ConnectionInfo and **SecPkgContext_CipherInfo**, 716 bytes on x64. With the short 9-DWORD layout it fails with 122. When the handshake failed, the query still succeeds but returns zeros. | round1 `conninfo err=122`; round2 `size=716 ... suite=0xc030` | mingw lacks the option and the struct, so define both in the test. This is also a good negative test. |
| F11 | wininet aborts the TCP connection during or after the handshake when verification fails. The server sees `recv=0` mid-handshake, or a completed handshake followed by close with no request. | `*_srv_tls hs_recv=0`, `app_recv=0` | The TLS server must treat EOF anywhere as normal and not count it as a failure. The wire recorder logs it as a connection event (`SRV_EV_TLS_ABORT`). |
| F12 | Wire facts (HTTP/1.1). `InternetOpenUrl(..., INTERNET_FLAG_RELOAD)` sends only `GET /p HTTP/1.1`, `User-Agent`, `Host` (with `:port`), `Cache-Control: no-cache` in that order: no Accept, no Connection. A request handle **re-sent** after a cert error added `Connection: Keep-Alive`; a first send did not. | `*_wire`, `*_srv` lines | Do not hard-code header sets from this probe. The recorder makes them assertable, and each header fact needs its own targeted test. The keep-alive difference is unexplained so far (note only). |
| F13 | FTP over loopback with PASV works. The client command sequence for connect, `FtpGetCurrentDirectory` and `FtpFindFirstFile(NULL)` is `USER anonymous`, `PASS`, `PWD`, `TYPE A`, `PASV`, `LIST` (no SYST, FEAT or OPTS). The `LIST` line parses to name `hello.txt`, size 5. | `ftp cmds` | A small scripted FTP server is enough (section 1.4). |
| F14 | Guest clock: UTC 23:25 while the host was 00:25 UTC, so the **guest is about 1 h behind** (RTC=localtime, guest TZ PST, tzid 1). | `clock` | Servers live in the guest and use guest time for Date, Expires and cookie expiry: always compute relative to `GetSystemTime` in the test. Never mix in host time. |
| F15 | VM loop costs: the run starts at 0 s and the **first COM1 byte arrives at 34 s** (logon plus HKLM Run hook; guest uptime 33.6 s at exe start). A full payload of 2.7 s of probes took **49.6 s** host wall time, the second payload 63 s. Serial throughput: unbuffered `printf > COM1` **38 KB/s**, buffered or direct WriteFile to COM1 **~245 KB/s**, through the vmrun pipe the child sees 371 KB/s and the COM1 drain is ~246 KB/s (2 MB in 8.9 s). | `size_trace`, `spew`, `com1_direct`, `big` | Budget per boot is about 40 s overhead, plus 4 s per MB of output, plus test time. One boot can carry the whole corpus. |
| F16 | COM1 is exclusive. A second opener gets "Access is denied" and its output is **lost silently**: `cmd` still reports errorlevel 0. | `contend` | Exactly one writer at a time. The exe never opens COM1 itself, and `vmrun.exe` owns it per run (section 2). |

## 1. In-process server library (`common/srv.h`, `common/srv.c`)

### 1.1 Principles
- **Loopback only, ephemeral ports.** Bind `127.0.0.1:0`, read the port back with `getsockname`, then bind `[::1]:<same>`
  with `SO_EXCLUSIVEADDRUSE` (F2). If the v6 bind loses the race (port taken), close both and retry with a new
  v4 port, at most 8 times. Fall back to v4-only with a `t_note` (localhost then costs 2 s; see F2).
- **Resolved at run time, not linked.** The library reaches ws2_32, secur32/sspicli, crypt32 and ncrypt through its own
  `GetProcAddress` table (`srv_api`). It is not import-linked, which has three effects:
  - the Makefile stays at kernel32/advapi32/ntdll;
  - on Industrial7 a missing export in, for example, crypt32 becomes a SKIP for HTTPS tests instead of a loader failure for
    the whole exe;
  - areas that test ws2_32 or crypt32 behaviour are not perturbed by load-time imports.

  Missing pieces make `srv_start` fail with `SRV_E_UNAVAILABLE`. Tests then `t_skip("server unavailable: ...")`.
- **Never include `winhttp.h` and `wininet.h` in one TU.** They conflict (`URL_COMPONENTS`, `INTERNET_SCHEME`, ...). `srv.h`
  includes neither.
- **Bounded everything.** Accept polls with `select` at 100 ms. Every socket gets `SO_RCVTIMEO`/`SO_SNDTIMEO` of 5 s by
  default. Each server has a hard lifetime (default 20 s), after which it stops accepting and closes its sockets.
  At most 64 connections per server, one thread each.
- **Scripted, byte-exact responses.** The server never "helps": what the script says is what goes on the wire,
  including bad framing (short bodies, bad chunk sizes, bare LF, duplicate headers, close-delimited bodies).

### 1.2 API sketch
```c
typedef struct srv srv;                 /* opaque */
typedef enum { SRV_HTTP, SRV_HTTPS, SRV_FTP } srv_kind;

/* One step of a per-connection script. A connection runs steps in order; the script used by connection i
 * is scripts[min(i, nscripts-1)], so "first connection 401, second 200" is two scripts. */
typedef enum {
    SRV_RECV_HEAD,        /* read one request head (to CRLFCRLF); recorded */
    SRV_RECV_BODY,        /* read the body per Content-Length / chunked of the last head; recorded */
    SRV_RECV_BYTES,       /* read exactly n bytes (or to EOF if n=0); recorded */
    SRV_SEND,             /* send bytes verbatim (data, n) */
    SRV_SEND_FMT,         /* send printf-expanded text: %P = port, %H = Host header value, %R = request path */
    SRV_SEND_CHUNKED,     /* send data as chunked body with the given chunk size, terminating 0-chunk */
    SRV_SEND_GZIP,        /* send a canned gzip member of data (stored deflate: no zlib dependency) */
    SRV_SLEEP,            /* sleep n ms (<= 2000), e.g. to test receive timeouts */
    SRV_SHUT_WR,          /* shutdown(SD_SEND): close-delimited body end */
    SRV_RESET,            /* SO_LINGER{1,0} + close: RST */
    SRV_CLOSE,            /* graceful close, end of script */
    SRV_LOOP              /* jump back to step 0 (keep-alive: serve many requests on one connection) */
} srv_op;
typedef struct { srv_op op; const char *data; size_t n; } srv_step;
typedef struct { const srv_step *steps; int nsteps; } srv_script;

typedef struct {
    srv_kind kind;
    const srv_script *scripts; int nscripts;
    DWORD lifetime_ms;        /* default 20000 */
    DWORD io_timeout_ms;      /* default 5000 */
    int v4_only;              /* 0 = also [::1] (default) */
    int cert_profile;         /* HTTPS: SRV_CERT_LOCALHOST (default, SAN dns+ip), SRV_CERT_CN_OTHER (CN=i7-other.invalid, no SAN),
                                 SRV_CERT_EXPIRED (validity in the past), SRV_CERT_NO_EKU */
    DWORD tls_protocols;      /* 0 = schannel default (TLS 1.2 here); else SP_PROT_*_SERVER via SCH_CREDENTIALS */
    const char *ftp_root_listing; /* FTP: LIST payload; files served from a small in-memory table */
} srv_config;

int   srv_start(const srv_config *cfg, srv **out);          /* 0 or SRV_E_*; server is accepting on return */
unsigned short srv_port(const srv *s);
const char *srv_url(const srv *s, const char *path);        /* "http[s]://127.0.0.1:%u%s" in a per-server buffer */
void  srv_stop(srv *s);                                     /* see 1.5; always returns within 3 s */

/* Wire recorder */
typedef enum { SRV_EV_ACCEPT, SRV_EV_HEAD, SRV_EV_BODY, SRV_EV_BYTES, SRV_EV_FTP_CMD, SRV_EV_TLS_DONE,
               SRV_EV_TLS_ABORT, SRV_EV_EOF, SRV_EV_RESET, SRV_EV_SCRIPT_DONE } srv_ev_kind;
typedef struct { srv_ev_kind kind; int conn; const char *data; size_t n; DWORD tls_proto; } srv_event;
int   srv_wait_events(srv *s, srv_ev_kind kind, int count, DWORD timeout_ms); /* bounded wait for N events of a kind */
int   srv_events(srv *s, const srv_event **ev);             /* snapshot; valid until srv_stop */
int   srv_conn_count(srv *s);
/* Parsed view of request i (in arrival order) */
const char *srv_req_line(srv *s, int i);                    /* "GET /p HTTP/1.1" */
int   srv_req_header_count(srv *s, int i);
const char *srv_req_header_name(srv *s, int i, int h);      /* exact casing as sent */
const char *srv_req_header(srv *s, int i, const char *name); /* case-insensitive lookup, first match; NULL if absent */
const char *srv_req_body(srv *s, int i, size_t *n);         /* de-chunked; srv_req_raw() gives the bytes as sent */
const char *srv_req_raw(srv *s, int i, size_t *n);
```
Test usage:
```c
TEST(http_send_basic_wire) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { { SRV_RECV_HEAD }, { SRV_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 40 }, { SRV_CLOSE } };
    static const srv_script sc[] = { { st, 3 } };
    srv_config cfg = { SRV_HTTP, sc, 1 }; srv *s;
    if (srv_start(&cfg, &s)) { t_skip("server unavailable"); return; }
    HINTERNET hi = U(InternetOpenA)("t", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    ...
    CHECK(srv_wait_events(s, SRV_EV_HEAD, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET /p HTTP/1.1");
    srv_stop(s);
}
```

### 1.3 HTTPS (schannel server)
- **Certificate profiles** are created once per process, lazily, and reused by every HTTPS server in that process:
  - CNG key `MS_KEY_STORAGE_PROVIDER`, RSA 2048, persisted under the name `wininet_<pid>_<profile>`;
  - `CertCreateSelfSignCertificate` with `szOID_RSA_SHA256RSA` and `CRYPT_KEY_PROV_INFO` naming that key;
  - SAN {DNS:localhost, IP:127.0.0.1, IP:::1} and EKU serverAuth.

  The certificate stays in memory and is never added to any store. An `atexit` handler deletes the keys (`NCryptDeleteKey`).
  `SRV_CERT_EXPIRED` is created with an explicit start/end in the past: start = now-30 d, end = now-1 d, guest time (F14).
- **Credential**: `AcquireCredentialsHandleW(NULL, UNISP_NAME_W, SECPKG_CRED_INBOUND, ..., SCHANNEL_CRED v4 {cCreds=1})`,
  or `SCH_CREDENTIALS` v5 when `tls_protocols` is set. Both were verified (F7). Compile it with `SCHANNEL_USE_BLACKLISTS`
  for the v5 struct.
- **Handshake loop**: `AcceptSecurityContext` with `ASC_REQ_STREAM|CONFIDENTIALITY|SEQUENCE_DETECT|REPLAY_DETECT|EXTENDED_ERROR|
  ALLOCATE_MEMORY`, carrying `SECBUFFER_EXTRA` over and looping on `SEC_E_INCOMPLETE_MESSAGE`, at most 20 rounds. Then
  `DecryptMessage`/`EncryptMessage` with `SECPKG_ATTR_STREAM_SIZES`. Each script step works on plaintext, so scripts are
  identical for HTTP and HTTPS. When the script ends, send close_notify (`ApplyControlToken(SCHANNEL_SHUTDOWN)` plus one
  ASC). EOF at any point is recorded (`SRV_EV_TLS_ABORT`) and is not an error (F11). This design is prototyped in
  `proto.c serve_tls`.
- **Client side** (test guidance, F8/F9): set `INTERNET_OPTION_SECURITY_FLAGS` on the **request** handle before
  `HttpSendRequest`, query-OR-set: `0x100` for the default cert on either name, `0x1100` for `SRV_CERT_CN_OTHER`.
  Expected first-try errors: 12045, then 12038 for CN_OTHER after 0x100. `SRV_CERT_EXPIRED` is expected to give 12037
  (`ERROR_INTERNET_SEC_CERT_DATE_INVALID`) after 0x100. That is decomp/doc-derived and not yet measured: verify before a hard CHECK.
- Revocation: `CertificateRevocation=1` (F6) did not interfere with a self-signed leaf that has no CDP/AIA. Do not add CDP/AIA
  extensions: an offline fetch could stall up to the URL-retrieval timeout.

### 1.4 FTP server
One control connection per script. Built-in replies cover:

| Command | Reply |
|---|---|
| USER | 331 |
| PASS | 230 |
| PWD | 257 "/cwd" |
| CWD | 250 / 550 |
| TYPE | 200 |
| PASV | 227 (127,0,0,1,p1,p2), with a per-transfer v4 data listener |
| EPSV | 229 |
| LIST/NLST | 150 + data + 226 |
| RETR | 150 + bytes + 226 / 550 |
| STOR | 150 + recorded bytes + 226 |
| SIZE | 213 |
| MDTM | 213 |
| DELE, MKD, RMD, RNFR/RNTO | 250 |
| QUIT | 221 |

A test can override any reply through a `(command prefix -> reply)` table, which covers the error paths. Every command line
is recorded (`SRV_EV_FTP_CMD`) with PASS masked. Active mode (PORT) is out of scope: it needs an inbound connection from the
server to the client, so wininet tests use `INTERNET_FLAG_PASSIVE`. A test that uses active mode notes it. Verified client
sequence: F13.

### 1.5 Threading and shutdown guarantees
- One accept thread per server, plus one thread per connection (<= 64), joined by `srv_stop`.
- `srv_stop` does the following:
  1. sets `stop`;
  2. closes the listen sockets, which unblocks `select`;
  3. calls `shutdown(SD_BOTH)` and `closesocket` on every live connection socket (the list is guarded by a CS), which
     unblocks `recv`/`send` in the connection threads;
  4. waits for all threads, max 3 s in total.

  A thread that is still alive after that is reported with `t_note("srv: thread leak")`. It is not terminated, since
  `TerminateThread` could orphan a loader or heap lock; it is left to die at process exit. In the prototype, stop took
  98-109 ms (the accept poll interval) with no leaks.
- The `srv` object stays valid until `srv_stop`. The event log is copied out under the CS, so tests read it without racing.
- A server must be stopped **after** the wininet handles that use it are closed. Otherwise wininet keep-alive sockets
  get reset, which is harmless but noisy. Recommended order: `InternetCloseHandle(req/conn/session)`, then `srv_stop`.
- Lifetime cap: a server that is never stopped (test crash, VEH longjmp) shuts itself down after `lifetime_ms`, so the next
  test is not stalled. Ports are never reused between servers because each server binds a fresh ephemeral port.

### 1.6 Port selection
Ephemeral (`bind :0`) only. On this image the ports start around 49670 (F1). No fixed ports, so parallel exes and
TIME_WAIT never collide. `SO_EXCLUSIVEADDRUSE` stops a stray process from hijacking the port. Host-side servers through
`W10_NETEXTRA` (guestfwd 10.0.2.100:8080) are kept for the rare case that needs a non-loopback address. They are not used
by default, because that path does not work under Industrial7 or bare Windows reruns without the same QEMU.

## 2. Results protocol and runner

**Decision: neither plain `cmd` redirection nor the exe writing COM1.** A small guest runner, `vmrun.exe`
(prototype: `tools/proto/vmrun.c`; the foundation role moves it to `tools/vmrun.c` and builds it from the Makefile):

    vmrun.exe [-t SECONDS] [-o \\.\COM1|file] [-n NAME] -- EXE [ARGS]

What it does:
- opens COM1 once (115200 8N1, 30 s write timeout);
- starts the child **suspended**, puts it in a job with `KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION`, `SEM_NOGPFAULTERRORBOX`
  inherited and stdin=NUL, then resumes it;
- pumps the child's stdout+stderr pipe into COM1 in 16 KB writes;
- frames each run as `@@I7 BEGIN <name> <cmdline>` ... `@@I7 END <name> exit=0x.. ms=N timeout=0|1 bytes=N`.

Why each alternative loses (F15, F16):
- `exe > COM1`: the harness's `_IONBF` printf turns into one serial write per call, which is 38 KB/s (6.5x slower). A
  hung exe stalls the boot until the 900 s QEMU timeout, and a crash gives no exit code in the log.
- The exe writing COM1: it collides with `cmd`'s own `> COM1`. The second opener is denied and the loss is silent (F16).
  Every corpus exe would also need VM-specific code, and the same exes must run unchanged on real Windows by another lane.
- vmrun avoids both. Measured on the VM: a hang killed at the deadline (`exit=0xdead0001 ms=4995 timeout=1`), a crash
  reported with no WER stall (`exit=0xc0000005 ms=18`), and 2 MB moved in 8.9 s.

`tools/vm_run.sh` (host, foundation role) does three things:
1. Stages `build/*.exe`, `vmrun.exe` and a generated `run.cmd` into a payload dir. For each exe the `run.cmd` has
   `vmrun.exe -t <per-exe> -n <area> -- <area>.exe` and nothing else writing COM1 while vmrun runs.
   `dx_*` areas are included only with `--destructive`.
2. Calls `~/w10lab/tools/win10_run.sh PAYLOAD OUT` with `ORACLE_TIMEOUT` = sum(per-exe timeouts) + 120 s (boot +
   drain) and a cap of 900 s. If the cap would be exceeded, it splits into several boots. The lock serialises them.
3. Splits `serial.log` on the `@@I7 BEGIN/END` frames into `results/<area>.txt`, the same layout as `run_all.bat`, so
   `tools/summarize.py` works unchanged. An area without an END frame is reported as `CRASHED/TRUNCATED`. An END with
   `timeout=1` is reported as `TIMEOUT`, never as pass.

Timeouts: the default per exe is 120 s, and an area may declare more in a comment in its directory. The
`Sleep`/`WaitFor` bounds inside tests stay at a few seconds (SAFETY). Output size: about 4 s per MB on COM1.
The corpus summary is well below 1 MB, so one boot usually covers everything (about 40 s boot plus test time).

Scratch and state: the payload ISO is read-only, so tests write to `%TEMP%` (`t_tmpdir`). The overlay is thrown away
after each boot, so cache/cookie leftovers cannot leak between boots. Tests must still clean up (SAFETY): reruns on a
persistent Windows box are expected.

## 3. Risks

| Risk | Mitigation |
|---|---|
| A refused-connect or localhost-on-v4-only test silently adds 2-4 s (F2/F3), and areas creep toward the timeout. | Dual-stack default; IP literals in URLs; reviewers flag refused-connect tests; vmrun reports `ms`. |
| The image or network changes make WPAD or autodetect slow (DHCP 252, DNS suffix, a host-side DNS). | DIRECT everywhere outside proxy areas. Proxy areas bound each call (`INTERNET_OPTION_CONNECT_TIMEOUT`, worker-thread with an outer wait) and note the timing instead of asserting it. |
| `SecureProtocols=0x800` (TLS 1.2 only) is a property of this image, not of the OS default. | Assert protocols only after setting them explicitly per session; record the registry value with `t_note`. |
| The wininet security cache (`SECURITY_CACHE_LIST`, `HandleCachedServerCert`) could tie results to test order for client-cert or revocation state. F9 shows that ignore flags are not cached. | A fresh server, and so a fresh port, per test. Never reuse a host:port across tests that assert cert outcomes. |
| COM1 contention loses output silently (F16). | Only vmrun writes during runs. `run.cmd` echoes only between vmrun calls. |
| A guest wedges (hang outside a vmrun deadline, a dialog). | `INTERNET_FLAG_NO_UI` on every request. No `InternetErrorDlg` without `FLAGS_ERROR_UI_FLAGS_NO_UI`. `ORACLE_TIMEOUT` caps the boot. A missing END frame becomes a visible TRUNCATED. VNC (`W10_VNC`) lets a human look at a wedged guest. |
| The guest clock is about 1 h behind the host (F14), and the cert/cookie/cache expiry logic depends on time. | All times come from the guest (`GetSystemTime`). No host-side Date headers. Expiry tests use +-days margins, not minutes. |
| Crypto keys leak into the Administrator's key store on persistent Windows. | Per-pid key names, `atexit` delete, and a leftover sweep of `wininet_*` keys at the start of HTTPS areas. |
| The server library itself depends on APIs that Industrial7 may not have (CertCreateSelfSignCertificate, schannel server-side). | Runtime resolution, with `SRV_E_UNAVAILABLE` turned into a SKIP. HTTP and FTP need only ws2_32. |
| Two workflows want the VM at once. | `win10_run.sh` holds `~/w10lab/oracle.lock`. Batch whole areas into one boot and never start qemu directly. |
| One-boot results are trusted when they are flaky (timing, ephemeral ports). | Anything timing-related is `t_note` only. Before a CHECK is promoted, the area is run in two separate boots. |

## 4. Reproduce
    tools/proto/build.sh run.cmd   && ~/w10lab/tools/win10_run.sh tools/proto/out ~/w10lab/runs/wininet-proto1
    tools/proto/build.sh run2.cmd  && ~/w10lab/tools/win10_run.sh tools/proto/out ~/w10lab/runs/wininet-proto2
