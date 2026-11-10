# Loopback test servers (`common/srv.h`) and WinINet helpers (`common/tnet.h`)

Every wininet test that needs a peer starts one in-process. The servers listen on `127.0.0.1` and `[::1]`, on the
same ephemeral port, and never on any other address. No test touches the internet. Design rationale and
the Win10 measurements behind these rules are in `docs/research/04_server_and_vm_design.md`; findings are cited as
F1..F16.

| File | Contents |
|---|---|
| `srv.h` | public API (the only header tests include) |
| `srv_core.c` | runtime API loading, listener, threads, recorder, accessors, data helpers |
| `srv_http.c` | connection IO, request parser, script engine, canned replies, SSPI (NTLM/Negotiate) server auth |
| `srv_tls.c` | certificate profiles, schannel server (handshake, records, close_notify) |
| `srv_ftp.c` | FTP server (control + PASV/EPSV/PORT/EPRT data) |
| `srv_data.c` | precompressed gzip/zlib/raw-deflate bodies |
| `tnet.h/.c` | `t_inet_open` (DIRECT + timeouts), `t_http_get`, unique cache/cookie names, cleanup registries, error names |

The Makefile links every `common/*.c` into every area. Nothing new is import-linked. ws2_32, sspicli (or secur32),
crypt32 and ncrypt are all resolved with `GetProcAddress`. If one is missing, as can happen on Industrial7,
`srv_start` returns `SRV_E_UNAVAILABLE` and the test calls `t_skip`. The loader does not fail the whole exe.

## Quick start

```c
#include "t.h"
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

TEST(area_get_example) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, "Content-Type: text/plain\r\n", "hi"), S_LOOP() };
    srv *s = srv_http(st, 3);
    if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open("my-agent");                 /* DIRECT, 5 s timeouts */
    char body[64]; size_t n; DWORD err;
    EXPECT_EQ(t_http_get(hi, srv_url(s, "/p"), NULL, T_INET_FRESH, body, sizeof body, &n, &err), 200);
    EXPECT_STR(body, "hi");
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET /p HTTP/1.1");
    EXPECT_STR(srv_req_header(s, 0, "User-Agent"), "my-agent");
    t_inet_close(hi);                                        /* close wininet handles first ... */
    srv_stop(s);                                             /* ... then stop the server */
}
```

`srv_http(NULL, 0)` serves the built-in script: every request gets `200` with body `hello`, and the connection is kept
alive.

## Server configuration (`srv_config`)

| Field | Default | Meaning |
|---|---|---|
| `kind` | `SRV_HTTP` | `SRV_HTTP`, `SRV_HTTPS`, `SRV_FTP` |
| `scripts`, `nscripts` | built-in | connection *i* runs `scripts[min(i, nscripts-1)]` ("first connection 401, second 200" = two scripts) |
| `lifetime_ms` | 20000 (max 120000) | after this the server stops accepting and resets live connections |
| `io_timeout_ms` | 5000 | `SO_RCVTIMEO`/`SO_SNDTIMEO` per connection |
| `v4_only` | 0 | 1 = no `[::1]` listener (`localhost` then costs ~2 s, F2) |
| `cert_profile` | `SRV_CERT_LOCALHOST` | HTTPS certificate, see below |
| `tls_protocols` | 0 (schannel default) | `SP_PROT_*_SERVER` bits to **enable** (via `SCH_CREDENTIALS` v5, with a fallback to `SCHANNEL_CRED`) |
| `tls_client_cert` | 0 | 1 = request a client certificate (`ASC_REQ_MUTUAL_AUTH`), 2 = also drop the connection without one |
| `ftp` | NULL | `srv_ftp_config *` |
| `user` | NULL | passed to `SRV_CALL` callbacks |

`srv_start(&cfg, &s)` returns `SRV_OK` with the server already accepting. `srv_stop(s)` sets the stop event, closes
the listeners, shuts down every connection socket and joins all threads, waiting at most about 3 s in total. A thread that is
still stuck after that is reported with `t_note("srv: thread leak")`. The server object is then leaked on purpose
and never `TerminateThread`ed.

URLs: `srv_url(s, "/p")` gives `http://127.0.0.1:<port>/p` (the scheme follows `kind`). `srv_url_host(s, "localhost", "/p")`
and `srv_url_host(s, "[::1]", "/p")` give the same URL on another host, and `srv_hostport(s)` gives `127.0.0.1:<port>`. Each server
has 8 rotating URL buffers.

## Scripts (HTTP and HTTPS)

A script is an array of `srv_step`. Each connection runs it from step 0. Scripts work on plaintext, so the same
script serves HTTP and HTTPS. Steps are built with the `S_*` macros:

| Macro | Op | Effect |
|---|---|---|
| `S_HEAD()` / `S_HEAD_EXPECT("GET /x")` | `SRV_RECV_HEAD` | read one request head (to CRLFCRLF or LFLF; an oversize head over 256 KB is taken as is). It is recorded as request *i*. EOF before a complete head ends the connection quietly. With a prefix, a request line that does not start with it is recorded as `SRV_EV_MISMATCH` |
| `S_BODY()` | `SRV_RECV_BODY` | read the body of the last head: Content-Length, or chunked (extensions and trailers allowed; both the de-chunked and the raw body are kept). No framing means no body |
| `S_BYTES(n)` | `SRV_RECV_BYTES` | read exactly n bytes (0 = to EOF), recorded as `SRV_EV_BYTES` |
| `S_SEND("raw")`, `S_SENDN(p,n)` | `SRV_SEND` | send bytes verbatim: bad status lines, bare LF, duplicate headers, anything |
| `S_FMT("Location: http://127.0.0.1:%P/x")` | `SRV_SEND_FMT` | send with `%P` port, `%H` Host of last request, `%R` its request-target, `%S` scheme, `%%` |
| `S_SPLIT("raw", piece, ms)` | `SRV_SEND_SPLIT` | send in pieces of `piece` bytes with `ms` between them (TCP_NODELAY is on) |
| `S_CHUNKED("body", csz)` | `SRV_SEND_CHUNKED` | a chunked *body* only (chunks of csz, then `0\r\n\r\n`). Send the head first with `S_SEND` |
| `S_PATTERN(n)` | `SRV_SEND_PATTERN` | n bytes of `srv_pattern_byte(i)`, checked with `srv_pattern_check()` |
| `S_REPLY(code, hdrs, "body")` | `SRV_REPLY` | canned response (below) |
| `S_REPLYF(code, hdrs, "body", flags)`, `S_REPLYN(code, hdrs, p, n, flags)`, `S_REPLY_CHUNKED(code, hdrs, "body", csz)`, `S_REPLY_PATTERN(code, hdrs, n, flags)` | `SRV_REPLY` | variants |
| `S_100()` | `SRV_REPLY_100` | `HTTP/1.1 100 Continue` if the last head had `Expect: 100-continue` |
| `S_SLEEP(ms)` | `SRV_SLEEP` | at most 5000 ms, interrupted by `srv_stop`. Use it for receive-timeout tests |
| `S_SHUTWR()` | `SRV_SHUT_WR` | `shutdown(SD_SEND)` (TLS: close_notify first) |
| `S_RESET()` | `SRV_RESET` | abortive close (RST) |
| `S_CLOSE()` / `S_END()` | | graceful close |
| `S_LOOP()` / `S_LOOP_TO(i)` | `SRV_LOOP` | jump (keep-alive), at most 1000 jumps per connection |
| `S_CLOSE_IF_ASKED()` | | close if the last request said `Connection: close` (or was HTTP/1.0 without keep-alive) |
| `S_CALL(fn)` | `SRV_CALL` | `int fn(srv_conn *c, const srv_step *st, void *user)`. Return < 0 to end. Inside it use `srv_conn_send/sendf`, `srv_conn_recv_head` (reads head and body, returns the request index), `srv_conn_last_req` |
| `S_AUTH("NTLM")` / `S_AUTH("Negotiate")` | `SRV_AUTH_SSPI` | server-side SSPI. Loops head -> `401 WWW-Authenticate: <pkg> [token]` until `AcceptSecurityContext` completes (at most 6 legs) and records `SRV_EV_AUTH` (`ok <user>` or `fail 0x<status>`). A final mutual-auth token is added to the next `SRV_REPLY` |

### Canned replies (`SRV_REPLY`)
The status line is `HTTP/1.1 <code> <standard reason>`. `hdrs` lines are copied after it, `%`-expanded like
`S_FMT`. Then come the framing headers and the body. The library adds nothing else: no Date, no Server, no Content-Type.

| Flag | Effect |
|---|---|
| (none) | `Content-Length: n` (omitted for 1xx/204/304 with an empty body) |
| `SRV_R_CHUNKED` | `Transfer-Encoding: chunked`, chunk size `step.n2` (0 = one chunk) |
| `SRV_R_CLOSE` | no length header. The body is close-delimited and the script ends |
| `SRV_R_GZIP` / `SRV_R_DEFLATE` / `SRV_R_RAWDEFLATE` | encode the body with stored deflate blocks (gzip / zlib / raw) and add `Content-Encoding` |
| `SRV_R_NO_LENGTH` | no framing header at all |
| `SRV_R_BODY_ON_HEAD` | send the body even when the request was HEAD (normally suppressed) |
| `SRV_R_HTTP10` | `HTTP/1.0` status line |
| `SRV_R_KEEPALIVE` / `SRV_R_CONN_CLOSE` | add `Connection: Keep-Alive` / `Connection: close` (the second also closes) |
| `SRV_R_TRUNCATE` | announce the full length, send half, close |

`data == NULL` with `n > 0` sends n pattern bytes. For real Huffman-compressed bodies, `srv_fox_gzip`, `srv_fox_zlib`
and `srv_fox_raw` (with `_len`) decode to `srv_fox_text()`, which is 900 bytes. Pass one with
`S_REPLYN(200, "Content-Encoding: gzip\r\n", srv_fox_gzip, srv_fox_gzip_len, 0)`. `srv_deflate_stored()`,
`srv_crc32()`, `srv_b64()` and `srv_unb64()` are available for building other bodies, such as Basic credentials or corrupt gzip.

Patterns for common cases:
```c
/* redirect then target, same connection */
{ S_HEAD(), S_REPLY(302, "Location: /dst\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP_TO(2) }
/* absolute redirect to self */
{ S_HEAD(), S_REPLY(301, "Location: http://127.0.0.1:%P/b\r\n", ""), ... }
/* Set-Cookie */
{ S_HEAD(), S_REPLY(200, "Set-Cookie: k=v; Path=/\r\n", "c"), S_LOOP() }
/* 407 / 401 challenge then success */
{ S_HEAD(), S_REPLY(401, "WWW-Authenticate: Basic realm=\"r\"\r\n", "no"), S_HEAD(), S_REPLY(200, NULL, "yes"), S_LOOP_TO(2) }
/* malformed: no headers at all (HTTP/0.9-style) */
{ S_HEAD(), S_SEND("just bytes"), S_CLOSE() }
/* receive timeout: answer after 3 s (set INTERNET_OPTION_RECEIVE_TIMEOUT 1000 in the test) */
{ S_HEAD(), S_SLEEP(3000), S_REPLY(200, NULL, "late") }
/* upload with Expect: 100-continue */
{ S_HEAD(), S_100(), S_BODY(), S_REPLY(200, NULL, "ok") }
```

## Wire recorder
Everything the client did is recorded per server, in arrival order:

- **Requests**: `srv_req_count`, `srv_wait_requests(s, n, ms)`, and the following accessors:
  - `srv_req_line`, `srv_req_method`, `srv_req_target`;
  - `srv_req_header_count`, `srv_req_header_name(i, h)` (exact casing and order), `srv_req_header_value`,
    `srv_req_header(i, "name")` (case-insensitive, first match), `srv_req_header_index`, `srv_req_header_occurrences`;
  - `srv_req_head_raw` (bytes exactly as sent), `srv_req_body` / `srv_req_body_raw` / `srv_req_body_chunked`;
  - `srv_req_conn(i)`, which tells which TCP connection carried request *i*. Compare it across requests to
    prove keep-alive reuse.
- **Events**: `srv_wait_events(s, kind, n, ms)`, `srv_count_events`, `srv_events` (a snapshot copy), and `srv_dump(s)`, which
  `t_note`s all of them. The kinds are:
  - `ACCEPT`, `HEAD`, `BODY`, `BYTES`, `SENT`;
  - `EOF`, `RESET`, `TIMEOUT`, `ERROR`, `CLOSED`;
  - `TLS_DONE` (`proto=0x.. cipher=0x.. suite=0x.. client_cert=0|1`), `TLS_ABORT` (the client gave up in the
    handshake, which is normal for certificate errors, F11);
  - `SCRIPT_DONE`, `MISMATCH`, `FTP_CMD`, `FTP_DATA`, `AUTH`.
- Waits are capped at 30 s. Use a few seconds.

## HTTPS
Certificate profiles are created once per process, on first use. Each is a persisted RSA-2048 key named
`wininet_<pid>_<profile>`: a CNG key (Microsoft Software KSP), or a CAPI key when CNG cannot be used, as under Wine.
`CertCreateSelfSignCertificate` signs it with sha256RSA. The certificate is never added to a store, and the keys are
deleted at exit (`atexit`).

| Profile | Subject / SAN / EKU / validity | wininet result on Win10 (F8, measured) |
|---|---|---|
| `SRV_CERT_LOCALHOST` | CN=localhost, SAN {DNS:localhost, IP:127.0.0.1, IP:::1}, serverAuth, now-1d..now+365d | no flags: 12045 `ERROR_INTERNET_INVALID_CA`; with `SECURITY_FLAG_IGNORE_UNKNOWN_CA` (0x100): 200 on `127.0.0.1` and `localhost` |
| `SRV_CERT_CN_OTHER` | CN=i7-other.invalid, no SAN, serverAuth | 0x100: 12038 `SEC_CERT_CN_INVALID`; 0x1100: 200 |
| `SRV_CERT_EXPIRED` | as LOCALHOST, now-30d..now-1d | see `results/win10/net_loopback.txt` (`netlb_https_expired_cert`) |
| `SRV_CERT_NO_EKU` | as LOCALHOST without EKU | not measured yet |
| `SRV_CERT_CLIENT` | CN=i7-client, clientAuth | for `INTERNET_OPTION_CLIENT_CERT_CONTEXT` tests (`srv_cert_get`) |

Client side rules (F8/F9): set `INTERNET_OPTION_SECURITY_FLAGS` on the **request** handle before
`HttpSendRequest`, using query-OR-set (`t_https_secflags(hreq, 0x100)`). Ignore flags are not remembered across
requests, and on a session handle the option fails with 12018. Start a fresh server, and so a fresh port, for each test that
asserts certificate outcomes. `srv_cert_get(profile)` returns the server certificate, for example to compare against
`INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT`.

TLS versions: the lab image limits wininet to TLS 1.2 (`SecureProtocols=0x800`, F6), and schannel there negotiates
TLS 1.2 with ECDHE_RSA_AES_256_GCM_SHA384 (0xC030). TLS 1.3 server support on 19041/19045 is not enabled
by default. With `tls_protocols = SP_PROT_TLS1_3_SERVER` the credential may fail, and the test then skips.

## FTP
```c
static const srv_ftp_file files[] = { { "/hello.txt", "hello", 5, "20200102030405" }, { "/pub/", NULL, -1 } };
static const srv_ftp_override ov[] = { { "RETR secret", "550 Permission denied.", 0 } };
srv_ftp_config fc = { files, 2, ov, 1 };
srv_config cfg = { SRV_FTP }; cfg.ftp = &fc;
```

- **Commands**:
  - USER/PASS (any login is accepted), SYST, FEAT, OPTS, NOOP, PWD, CWD/CDUP, TYPE, MODE, STRU, ALLO;
  - PASV/EPSV (v4 data listener, 5 s accept bound) and PORT/EPRT (loopback addresses only);
  - LIST/NLST (unix `ls -l` format, filtered by path or wildcard);
  - RETR (honours REST), STOR/APPE (stored in memory: `srv_ftp_file_data(s, "/name", &n)`), SIZE, MDTM, DELE, MKD, RMD,
    RNFR/RNTO, REST, ABOR, QUIT;
  - anything else gets `502`.
- **Overrides** win over built-ins. They match a case-insensitive command prefix, and `times` limits them to the first n matches.
- **Recording**: every command line is recorded (`srv_ftp_cmd(s, i)`, `SRV_EV_FTP_CMD`). PASS is masked as
  `PASS ***` unless `record_pass` is set. Use dummy passwords only.
- **Measured client sequence** (F13 and `netlb_ftp_*`): `USER anonymous`, `PASS`, then `TYPE I`, `PASV`, `RETR name` for
  `FtpOpenFile`. Wininet tests use `INTERNET_FLAG_PASSIVE`.

## Proxy / WPAD and determinism (`tnet.h`)
- **Proxy settings.** `t_inet_open(agent)` = `InternetOpenA(agent, INTERNET_OPEN_TYPE_DIRECT)` with 5 s connect, send and receive
  timeouts. `INTERNET_OPEN_TYPE_PRECONFIG` applies the per-user IE settings, and auto-detect (WPAD) is **on** by default
  (`DefaultConnectionSettings` flag 0x8). In the lab guest WPAD fails within a millisecond (F4: no DHCP option 252, no DNS),
  but on another network it means DNS lookups for `wpad.<suffix>`, DHCP INFORM, and possibly a real proxy. Those are slow and
  non-deterministic. Only proxy-area tests use PRECONFIG/PROXY. They run the call on a worker thread with an outer
  wait, and `t_note` the timings.
- **Address literals.** Use `127.0.0.1` in URLs. `localhost` resolves `::1` first. The servers listen on both, so it works in about 1 ms, but a
  v4-only peer costs about 2 s (F2). Refused connects cost about 2 s each (F3), so a few per area at most.
- **Cache and cookies.** Requests that are not about caching or cookies use `T_INET_FRESH` (RELOAD | NO_CACHE_WRITE | PRAGMA_NOCACHE | NO_UI |
  NO_COOKIES), so the URL cache and the cookie jar are neither read nor written.
- **Cache/cookie tests.** Use unique names: `t_uniq_cache_url("tag")` (auto-registered for deletion),
  `t_uniq_cookie_url("tag")` and `t_uniq_host("tag")`, all of the form `wininet<pid>n<seq>tag.i7test.example`. Register what you create with
  `t_cache_track(url)` and `t_cookie_track(url, name)`. `t_net_cleanup()` flushes both registries; it also runs at
  exit. Cookies for `127.0.0.1` are not port-scoped, so a wire cookie test should use a unique path from `t_uniq("p")`.
- **Environment note.** `t_net_prepare()` (called by `t_inet_open`) prints one `NOTE net env:` line with ProxyEnable,
  AutoConfigURL, autodetect, SecureProtocols and CertificateRevocation. It reads only, and never changes them; only `dx_*` areas may.
- **Error names.** `t_inet_errname(err)` maps a WinINet error code to its name for failure messages.

## Rules of thumb
- Close wininet handles before `srv_stop`. Otherwise pooled keep-alive sockets are reset, which is harmless but noisy.
- Use one server per test and never share ports between tests. Ports are ephemeral and never reused.
- Never assert timing. `t_note` it instead.
- Assert what the client sent with the recorder, and add each header fact as its own targeted test after verifying it
  on the VM (F12).
- `INTERNET_FLAG_NO_UI` is in `T_INET_FRESH`. Never call `InternetErrorDlg` without `FLAGS_ERROR_UI_FLAGS_NO_UI`.
