# http_request_wire: evidence

What the WinINet client puts on the wire. Every assertion reads the loopback server's recorder (`common/srv.h`):
request line, header names in send order with exact casing, values, bodies, and which TCP connection carried each
request.

Sources, as tagged below:

- **D** means decomp-grounded: the Win10 22H2 corpus (wininet.dll 10.0.19041), cited by function@RVA.
- **V** means observed on the local Win10 22H2 VM. The run is named by its boot.
  - Boots 1 and 2 (2026-11-09): the first WIP commit.
  - Boot C1 (2026-11-10): the first complete run, including `wire_addhdr.c`, which had never run before.
  - Boot C2 onward: confirmation runs.
- **K** means knowledge only, with no VM confirmation yet. Such items are `t_note`, never hard checks.

## Files
| File | Topic |
|---|---|
| `wire_defaults.c` | request line, default header set, order and casing, flags, verbs, object names, version, Referer, Accept, User-Agent, Host, re-send |
| `wire_addhdr.c` | `HttpAddRequestHeaders` A/W (ADD, ADD_IF_NEW, REPLACE, COALESCE*, lengths, malformed input, flags, handle types) and the headers passed to `HttpSendRequest` |
| `wire_body.c` | `lpOptional` bodies, `HttpSendRequestEx` + `InternetWriteFile` + `HttpEndRequest`, caller-framed chunked upload, `Expect: 100-continue` |
| `wire_conn.c` | keep-alive reuse, `Connection: close`, HTTP/1.0 servers, the per-server connection limit, proxy request form and CONNECT, Cookie and Authorization emission, cache revalidation |
| `wire_extra.c` | HTTPS request bytes, `InternetOpenUrl`, the decoding option, blocked ports, redirect follow-up requests |
| `wire_more.c` | `HttpQueryInfo(REQUEST_HEADERS)` against the wire, more add/replace edge cases, re-sends, CR/LF in caller strings, proxy bypass, cross-server redirects, keep-alive retry, cache validators |
| `wire_child.c` | facts that depend on per-process WinINet state, measured in a fresh child process (`exe --child ...`, results passed back through a temp file): non-ASCII object bytes, the per-server connection limit, and an encoding-flip probe |

## Infrastructure note (V)
WinINet keeps pooled keep-alive sockets after every handle is closed. A server connection thread that is blocked in
`recv()` is not woken by `srv_stop`'s `shutdown()`, so every `srv_stop` waited out its full 3 s deadline. Boot C1
measured this: each sending test cost exactly about 3.0 s, while a test that never sends cost 0.1 s. The same cost
appears in other areas, for example http_auth (146 tests in 458 s).

This area works around it: its servers use `io_timeout_ms = 1000` (`HRW_IO_MS`, `hrw_srv_cfg`). Tests that hold
unread 200 KB bodies keep 5000 ms. Boot C2 shows the effect: the area went from about 3 s per test to about 1 s, and
`hrw_zz_phase_timing` measured `srv_stop=1000` with every client phase near 0 ms. The proper fix belongs in `common/srv_core.c` `kill_conns`: close the socket
instead of calling `shutdown`, as `srv_stop` already does after its deadline. That fix is for the foundation role.

## Default request (V, boots 1, 2, C1; D for UA/Host/Content-Length)
- `GET /p HTTP/1.1`, then `User-Agent`, `Host`, `Cache-Control: no-cache` (with RELOAD). The raw head is exact
  (`hrw_def_get_raw_head_exact`). There is no Accept, Accept-Encoding, Connection or Pragma.
  - D `InitBeginSendRequest@0x88e20`: User-Agent is header index 0x27 and Host is index 0x37. Both are added with
    `_ReplaceHeader(..., 0x10000000)`, so a caller value wins.
  - Host is `"%s"` for port 80 (http) or 443 (secure), and `"%s:%d"` otherwise. A host of 0x10d characters or more
    fails with 87.
- Flags (V):
  - `RELOAD` or `PRAGMA_NOCACHE` gives `Cache-Control: no-cache`.
  - Neither flag gives just `User-Agent|Host`.
  - `KEEP_CONNECTION` adds `Connection: Keep-Alive` between Host and Cache-Control.
- Caller headers (HttpAddRequestHeaders before the send, or the headers passed to HttpSendRequest) come first. Then
  come User-Agent, Host, Content-Length and Cache-Control. Referer and Accept from HttpOpenRequest come before them all
  (V).
- POST, PUT, DELETE, OPTIONS, PATCH, custom and lowercase verbs carry `Content-Length: 0` without a body. GET and HEAD
  carry none.
  - D: `"%I32u"` of the optional length or `dwBufferTotal`, which is also written when the method index is greater
    than 1.
  - V: every verb in `g_verbs`. HEAD with optional data sends `Content-Length: 2` (V).
- A caller `Content-Length` is replaced by the real length. It keeps the caller's position (V).

## Request line (V unless noted)
- Version:
  - NULL, `""` and `"HTTP/1.1"` all give HTTP/1.1.
  - `HTTP/1.0`, `HTTP/0.9` and `http/1.0` are upgraded to `HTTP/1.1` (GlobalEnableHttp1_1). The global
    `INTERNET_OPTION_HTTP_VERSION` 1.0 is upgraded too.
  - `HTTP/1.2` and `HTTP/2.0` are sent verbatim. `http/1.1` is sent verbatim in lowercase.
  - `FOO`, `HTTP/` and `HTTP/a.b` are accepted, and give 1.1.
- Verbs:
  - Leading and trailing blanks are trimmed. Case is preserved.
  - `TRACE` and `track` fail with 12016.
  - An inner space, CR/LF, or blanks only fail with 87, and nothing reaches the wire.
- Object name:
  - NULL or `""` gives `/`, and a missing leading slash is added.
  - Dot segments are resolved (`/a/../b/./c` gives `/b/c`, and `/a/b/..` gives `/a/`). `/../x` is kept. `%2e%2e` is kept.
  - A space becomes `%20`. A tab, CR and LF are removed. `\` becomes `/`.
  - `*`, `?q` and `http://...` get a leading `/`. `#frag` is kept.
  - Bytes of 0x80 and above depend on **per-process state**.
    - In a process that has only made plain requests, they are sent raw. This was seen in boots C1 and C2, where each
      filtered group ran as its own process.
    - After the full suite has run in one process, they are percent-encoded as UTF-8, and an invalid byte becomes
      `%EF%BF%BD`. This was seen in boots 1 and C3, which ran the whole exe in one process.
    - The hard checks therefore run in a fresh child (`wire_child.c`), and `hrw_zz_encoding_flip_probe` notes which
      earlier operation flips the mode.
  - The W object name is UTF-8 (D `HttpOpenRequestW@0xbea10`). It is sent raw in a fresh process (V).
- InternetOpenUrl keeps a URL fragment in the request-target (boot C1).
- `HttpOpenRequestW` with a non-empty referer, ASCII or not, succeeds, but `HttpSendRequest` on that handle fails
  with **87** and nothing reaches the wire. This was seen in boots C1 and C2, in two tests each. An empty W referer
  works, and so does the A entry point with the same referer.

## Caller strings (V boot C1)
- A CR/LF inside the agent (InternetOpen), the referer, or an accept type cuts the string at the CR. No header can be
  injected.
- In an object name, CR/LF are dropped.
- The W agent is converted to ACP, so U+00E9 becomes byte 0xE9 (V boot 1, D `InternetOpenW`).

## HttpAddRequestHeaders (V boot C1 unless noted; D `HttpAddRequestHeadersA@0x88990`, `wHttpAddRequestHeaders@0x898d0`, `CHttpHeaders::AddHeaderByName@0x8ab70`)
- Lines may be separated by CRLF, LF, CR or LFCR. Blank lines are skipped.
- Whitespace around the name and the value is trimmed. A trailing extra `:` is stripped. Name casing is kept, and so
  is an inner space in a name.
- NULL, `""` or a length of 0 gives 87 (D, V). A bad flag gives 87 (D mask 0x08ff0000, V).
- A line without a colon, or with an empty name, or with an empty value without `ALLOW_EMPTY_VALUES`, gives 87. Lines
  before the bad one stay applied.
- In headers passed to HttpSendRequest the same errors give **12150**, and the request is not sent.
- `ADD` (or flags 0) appends, so duplicates are kept.
- `ADD_IF_NEW` on an existing header gives 12155. That includes the Referer and Accept created by HttpOpenRequest.
- `REPLACE`:
  - It removes the first occurrence and appends the new line at the end of the caller headers.
  - On an absent header it adds the line; there is no 12150.
  - An empty value removes the header.
  - The new name casing is used.
- `REPLACE|ADD_IF_NEW` on an existing header gives 12155. `REPLACE|COALESCE` replaces.
- `COALESCE`, `COALESCE_WITH_COMMA` and `COALESCE_WITH_SEMICOLON` join onto the first occurrence with `, ` or `; `
  (case-insensitive), or add when absent.
- User-Agent or Host set by the caller, including through REPLACE before the send or an empty UA with
  `ALLOW_EMPTY_VALUES`, win over the defaults. Their position and casing are kept.
- A header added after the first send lands after the defaults on the re-send.
- A re-send carries `Connection: Keep-Alive` at the end.
- HttpSendRequest headers persist on the handle and are not duplicated on later sends.
- A caller `Connection: close` is sent as `Connection: Close`.
- A caller `Proxy-Connection` is dropped on a direct connection.

## Bodies (V)
- `lpOptional` gives the exact bytes with Content-Length. There is no Transfer-Encoding or Content-Type unless the
  caller adds one.
- `HttpSendRequestEx`:
  - Content-Length comes from `dwBufferTotal`. The head leaves at `HttpSendRequestEx` time, before any write.
  - A NULL `lpvBuffer` forces the length to 0 (D).
- A caller `Transfer-Encoding: chunked` still gets `Content-Length: 0` (from `dwBufferTotal`), or the optional length
  with framing included.
- `Expect: 100-continue` from the caller is sent as given. A server that never sends 100 still gets the body.
- `HttpEndRequest` without `HttpSendRequestEx` gives 12017. `InternetWriteFile` before the send gives 12019.
- A POST re-sent on the same handle keeps the first send's **Content-Length** (boots C1 and C2).
  - With new optional data `"second"`, the head says `Content-Length: 3`, and a length-honouring server reads `sec`.
  - Without optional data, `Content-Length: 5` goes out with no body. The send then fails: in C2, 12152 after the
    server's I/O timeout.

## Connections (V)
- Keep-alive:
  - Three requests on one connect handle use one connection.
  - Two connect handles, or two sessions, share the pool.
- `Connection: close`, either from the caller or from the server, and a close-delimited body each give a new
  connection.
- HTTP/1.0 servers:
  - An HTTP/1.0 reply without keep-alive gives a new connection.
  - `HTTP/1.0` + `Connection: Keep-Alive` reuses the connection.
  - The client keeps sending HTTP/1.1.
- Per-server limit:
  - `MAX_CONNS_PER_SERVER` is 2 and `MAX_CONNS_PER_1_0_SERVER` is 4.
  - Setting it on a session handle gives 12016.
  - In a fresh process, a third concurrent request waits until a connection is drained, then reuses connection 0
    (boots C1 and C2).
  - After the full suite in one process, the third request got a third connection at once (boot C3). The check
    therefore runs in a fresh child (`hrw_child_limit_third_request_waits`).
- Dead pooled socket (RST, or FIN without a reply): the request is re-sent on a new connection and the caller sees
  200 (boot C1).
- Ignored-certificate TLS connections are not pooled. This matches the https_tls area.
- A single loopback TLS handshake occasionally fails with 12030 `CONNECTION_ABORTED`: on the 2nd attempt in boot C1,
  and on the 1st in C3. The pooling test retries a failed attempt (at most 5 in total) and checks the property on
  the requests that completed.

## Proxy (V)
- The request-target is absolute: `GET http://host[:port]/p HTTP/1.1`, with IPv6 hosts bracketed. Host carries a
  port only when it is not the default.
- The host in the request-target is lower-cased, while the Host header keeps the caller casing.
- An IDN host given to `InternetConnectW` goes out as punycode (`xn--bcher-kva...`) in both (boot C2).
- One proxy connection serves several origins.
- `INTERNET_OPEN_TYPE_PROXY` with a bypass list (`127.0.0.1` or `127.0.0.*`) sends matching hosts direct, in origin
  form. Other hosts go through the proxy (C2).
- With RELOAD the header set is `User-Agent|Host|Pragma: no-cache`. There is no Cache-Control and no
  Proxy-Connection on GET.
- HTTPS gives `CONNECT host:443 HTTP/1.0` with the headers
  `User-Agent|Host|Content-Length: 0|Proxy-Connection: Keep-Alive|Pragma: no-cache`.
- Proxy Basic auth: `Proxy-Authorization` is appended after `Proxy-Connection` on the retry.

## Cookies, auth, cache (V)
- A jar cookie is appended after Cache-Control as `Cookie: a=1; b=2`. NO_COOKIES suppresses both sending and storing.
- Basic auth:
  - The first request has no Authorization.
  - The retry on the same connection ends `...|Connection|Authorization`.
  - Later requests to the same path scope send it pre-emptively.
- Credentials in the URL are used only after a 401.
- Revalidation with RESYNCHRONIZE sends `If-Modified-Since` and/or `If-None-Match`, depending on which validators the
  response had, after Host. There is no Cache-Control.
- RELOAD sends no conditionals.

## Redirects (V boot C1)
- 302/303 turn POST or PUT into GET. Content-Length and Content-Type are dropped. Caller headers and Referer are kept.
  The follow-up ends with `Connection: Keep-Alive` on the same connection.
- 307 for a POST is not followed: 12168 `REDIRECT_NEEDS_CONFIRMATION`.

## Decoding (D + V)
`INTERNET_OPTION_HTTP_DECODING` does not add `Accept-Encoding`. D `_CheckDecompressionRequestHeaders@0x664d4` only
parses a caller-supplied value (gzip, deflate, br) to decide what to decode. A caller value is sent once, unchanged.

## Observations kept as notes (not hard checks)
- Changing the session agent after the request handle exists is now a hard check: the agent is taken at
  HttpOpenRequest time (V boots 2 and C2).
- The send error after a stale Content-Length depends on the server timeout, so only `!ok` is checked.
- The stored W referer value (`hrw_ref2_w_*`).
- The timing probe `hrw_zz_phase_timing`.
