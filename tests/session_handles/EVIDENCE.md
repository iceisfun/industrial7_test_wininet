# session_handles: evidence

This area covers InternetOpenA/W, InternetConnectA/W, InternetCloseHandle, handle types, per-handle-type
InternetQueryOption/InternetSetOption rules, status callbacks around handle lifetime, use of handles from
several threads, InternetAttemptConnect and InternetGetConnectedState(Ex). Test names start with `sh_`.

The oracle is genuine Windows 10 22H2 (10.0.19045, wininet 11.0.19041.2193) on the local QEMU guest, run with
`tools/vm_run.sh`. Every hard CHECK passed there (pass 1: 115-118 tests; pass 2: 202 tests, see "Pass 2" below). The tags below say where each expectation came from:

- **D**: read in the corpus decompilation (`/api/function/wininet/<fn>/decomp`), then confirmed on the VM.
- **VM**: measured on the VM and adopted as the expectation. The decompilation was silent, ambiguous or wrong.
- **K**: long-standing documented WinINet behaviour, confirmed on the VM.
- **note**: recorded with `t_note` only because the value depends on the environment, on timing or on undocumented state.

Wine was not used to set any expectation.

## Files
| file | topic |
|---|---|
| `sh.h` | helpers (`sh_open`, `sh_qdw`, `sh_htype`, `sh_parent`, FTP fixture, callback recorder) |
| `sh_open.c` | InternetOpenA/W: access-type table, proxy strings, agents, flags, PROXY info, named-proxy wire format, many sessions |
| `sh_connect.c` | InternetConnectA/W: services, handles, server names, ports and request URL, credentials, contexts, request, file:// and FTP handles |
| `sh_close.c` | InternetCloseHandle: NULL/garbage/double, tree teardown, HANDLE_CREATED/HANDLE_CLOSING, close from callbacks, close while another thread is blocked in a send |
| `sh_options.c` | query matrix (NULL / session / HTTP connect / request, A and W), set matrix, buffer protocol, FTP handle matrix |
| `sh_threads.c` | shared handles across threads, InternetAttemptConnect, InternetGetConnectedState(Ex) |
| `sh_more.c` | VM-measured defaults, handle-value shape, FTP handle lifetime, User-Agent on the wire |
| `sh_types.c` | handle type / parent / context / URL for every creating API (HttpOpenRequest SECURE, InternetOpenUrl http/ftp/file, FTP find/file/FtpCommand), option rules of the file: (14) and FTP handle kinds, cross-protocol APIs |
| `sh_setrules.c` | InternetSetOption(Ex): Ex flags, read-only / not-implemented / no-op option classes, PROXY on a session, REQUEST_PRIORITY, ERROR_MASK, SECURITY_FLAGS mask, buffer sizes, timeout edge values, CODEPAGE, credentials A/W, CONTEXT_VALUE as the callback context |
| `sh_life.c` | lifetime edges: hidden connects of InternetOpenUrl, wide trees, callbacks on part of a tree, re-entrant calls in HANDLE_CLOSING/HANDLE_CREATED, unread bodies, FTP trees, handle value reuse |
| `sh_flags.c` | OFFLINE / FROM_CACHE, named-proxy forms (scheme lists, bypass entries, loopback), VIA_PROXY, ASYNC session handle creation, FTP passive/active |
| `sh_conc.c` | racing closes, closing a parent under concurrent queries/creations, parallel trees, callback thread, concurrent SetStatusCallback, per-request options across threads |

## InternetOpen
| expectation | tag |
|---|---|
| access 0/1/3/4 accepted; every other value (2, 5..9, 0x10, 0x80000000, -1 ...) fails with 87, with or without a proxy string | D `InternalInternetOpen` `(access & ~4)==0 \|\| 1 \|\| 3` |
| PROXY with a NULL or "" proxy string fails with 87, in both A and W | D |
| a proxy string passed with DIRECT or PRECONFIG is accepted, and with DIRECT the PROXY option still reports DIRECT | VM |
| on success GetLastError()==0 | D `SetLastError(dwErrCode)` epilogue |
| no dwFlags value makes InternetOpen fail, including 0xffffffff | D (flags stored unvalidated) |
| NULL or "" agent: USER_AGENT reads "" with length 0, and no User-Agent header is sent | D `case 0x29` / `InitBeginSendRequest` |
| USER_AGENT query: A size query returns 122 with chars+1; W returns chars on success and (chars+1)*2 bytes on 122; NULL length gives 87 | D `InternetQueryOptionA` common tail, W wrapper |
| USER_AGENT set: "" gives 12010, NULL buffer or length 0 gives 87, the A length is ignored (NUL-terminated text), the W length counts characters | D `InternetSetOptionA case 0x29`, `InternetSetOptionW`; VM |
| leading and trailing blanks in the agent are kept in the option | VM |
| a W agent with non-ACP characters is stored as UTF-8 (`c3a9 e4b8ad`) | note (VM-observed; matches D `InternetOpenW` ACP-then-UTF-8 fallback) |
| PROXY info for a named proxy: access 3, lpszProxy "127.0.0.1:9", **lpszProxyBypass "127.0.0.1:9 <local>"**, size 56 | VM (unexpected: the session's bypass string carries the proxy list) |
| InternetQueryOptionW(PROXY) on a session returns the **A layout** (narrow strings, size 56), not wide strings | VM (quirk) |
| a request on a PROXY session goes to the proxy in absolute form `GET http://origin/...`, with Host = origin, the session User-Agent and no Proxy-Connection header | VM |
| a bypass-list host goes direct | K, confirmed on the VM |
| INTERNET_OPTION_ASYNC (30) gives 120 | D |
| VERSION is 1.2 (8 bytes, 122 with length 8 when the buffer is short); HTTP_VERSION is 1.1 | K/D, confirmed on the VM |
| 500 open/close cycles and 200 session/connect/request trees leave the kernel handle count unchanged (241 -> 241) | VM (CHECK allows +16) |
| session timeout defaults: CONNECT 60000, RETRIES 5, BACKOFF 0, SEND/RECEIVE/DATA_* 30000 | VM |

## InternetConnect
| expectation | tag |
|---|---|
| the service is checked first (before the handle and the server name): 0, 2 (GOPHER), 4.., -1 give 87 | D `InternetConnectA` `(svc-1)&~2` |
| a NULL or "" server name gives 87 (A) even with a garbage handle; W "" gives 123 ERROR_INVALID_NAME | D `HttpConnect` order; VM for W |
| NULL or garbage parent gives 6; a connect or request handle as parent gives 12018; a closed session gives 6 | D `MapHandleToAddress`/`IsValid('Inet')` |
| an HTTP connect does no I/O: any host name or port gives a handle; GetLastError()==0 | D/K |
| request URL (INTERNET_OPTION_URL) table: port 0 means 80, or 443 with connect SECURE; the scheme comes from the **request** SECURE flag; the port is printed only when it is not the scheme default | D `HttpConnect`, `HttpGetUrlString`; VM |
| a 599-character host: InternetConnect succeeds; HttpOpenRequest fails with 122 | VM |
| USERNAME/PASSWORD round-trip on connect (A/W); "" means NULL; requests inherit them; a request's own set does not change the connect | D `GetUserOrPass`/`SetUserOrPass`; VM |
| USERNAME/PASSWORD/PROXY_USERNAME/PROXY_PASSWORD on a session give 12018 (query and set) | D |
| credentials are used for Basic after a 401: `Authorization: Basic dXNlcjE6cHcx` on the second request only | K, confirmed on the VM |
| CONTEXT_VALUE: the dwContext parameter is readable (8 bytes); a set with length other than 8 gives 12010; a short query buffer gives 122 with length 8; children do not inherit it | D `case 0x2d`; VM |
| connect flags (PASSIVE, ASYNC, SECURE, EXISTING_CONNECT, -1) never fail for HTTP | D (flags masked) |
| REQUEST_FLAGS: session and connect give 12018; an unsent request reads 8 (NO_HEADERS); after a network GET with NO_CACHE_WRITE it reads 0x40 (CACHE_WRITE_DISABLED); an FTP find reads 8 | D `case 0x17`; values VM |
| KEEP_CONNECTION: valid on HCon only (value 0); 12018 elsewhere; set gives 12011 | D `case 0x16`; VM |
| InternetOpenUrl(http): the request (13) has a hidden HCon parent whose parent is the session; closing the request also closes the hidden connect (6 afterwards) | D close loop `+0x78`; VM |
| InternetOpenUrl(file:): `file://C:\dir\x` opens a type-14 handle whose parent is the session itself, and the body reads back; `file:///C:/dir/x` (forward slashes) fails with 3 ERROR_PATH_NOT_FOUND; `file:///C:\dir\x` is noted only | VM |
| FTP connect logs in immediately (`USER anonymous` with no credentials, USERNAME reads "anonymous"); handle type 2; connecting to a dead port gives 12029 | D/VM |
| FTP find handle type 5, file handle type 7, parent = FTP connect; a second find on a busy connect gives 12110 ERROR_FTP_TRANSFER_IN_PROGRESS; InternetOpenUrl(ftp) gives type 7 with a hidden FCon parent | K/D, confirmed on the VM |

## InternetCloseHandle
| expectation | tag |
|---|---|
| NULL, garbage values, double close: FALSE/6 | D, confirmed on the VM |
| on success GetLastError()==0 | VM |
| closing a session or connect invalidates every descendant (queries give 6; closing them afterwards gives 6); siblings and other sessions are untouched | D `InternalInternetCloseHandle` child loop; VM |
| a closed handle gives 6 for QueryOption (with *len 0), SetOption, HttpSendRequest, InternetReadFile, HttpQueryInfo and InternetSetStatusCallback (-1) | D |
| InternetSetStatusCallback: NULL handle gives -1/12018, garbage gives -1/6, the previous callback is returned, CALLBACK option reads it (set gives 12011), children copy it at creation only | D `InternetSetStatusCallbackCore`; VM |
| callbacks fire only for non-zero contexts; HANDLE_CREATED (60) carries the new handle; closing a session delivers HANDLE_CLOSING (70) to request, then connect, then session (children first) | K, order VM |
| closing a sibling, or the handle itself, from inside a callback works | VM |
| closing a request from its own REQUEST_SENT callback, from another thread during a blocked sync send, or by closing its session: the send fails with 12017 OPERATION_CANCELLED | K, VM |
| async session: closing a request whose send is pending completes it with REQUEST_COMPLETE {0, 12017} | VM (note + CHECK on the completion values) |

## Query/Set option matrix (`sh_options.c`)
The table in `sh_qtab` is the specification. It comes from the `InternetQueryOptionA` switch [D] and the VM boots.
Points worth knowing:
- NULL handle: per-process options are answered (timeouts, VERSION, HTTP_VERSION, PROXY, CONNECTED_STATE...). Other
  options give 12018 inside 1..0xC0 and 12009 outside, and A sets `*len = 0` [D `IsPerProcessOption`]. The W
  wrapper leaves `*len` unchanged for the string options it converts itself (VM).
- Real handle, unknown option (0, 193, 999, -1): **87** for query, **12009** for set (D/VM).
- MAX_CONNS_PER_SERVER is readable on an HTTP connect handle (4 bytes) but gives 12016 on a session or request; the
  decompilation guess of 12016 for connect was wrong (VM).
- SECURITY_CERTIFICATE(_STRUCT)/KEY_BITNESS on a plain-HTTP request give 12016; SERVER_CERT_CHAIN_CONTEXT gives 12019
  (note); DATAFILE_NAME on an unsent request gives 12028 (note).
- 54-57 and 70 give 50 on handles; 15/16/26/30 give 120. Set: CALLBACK, HANDLE_TYPE, KEEP_CONNECTION and ASYNC_ID give 12011;
  PARENT_HANDLE, REQUEST_FLAGS and URL give 12009 (VM, notes).
- Timeouts are per handle and copied from the parent when the child is created; a later change on the parent does not
  reach existing children (VM).
- **W + NULL lpdwBufferLength crashes Win10** for string options that the W wrapper converts itself (URL with a buffer:
  access violation in `InternetQueryOptionW` case 0x22). W is probed with a NULL length only for options below 0x1c,
  which go straight to A.

## Threads
| expectation | tag |
|---|---|
| 8 threads x 150 HttpOpenRequest/query/close on one shared connect: no failures | VM |
| 8 threads each building and closing their own trees: no failures. Handle values are reused across threads immediately, so the test never probes a closed handle | VM |
| USER_AGENT set by one thread while 4 threads query it: **reads can return a mixed value** (19 of 3509 in boot 1, 1 of 4150 in boot 2). Win10 rewrites the string without a lock. note only | VM |
| 4 threads x 5 GETs on one session against a keep-alive server: all 200 (20 requests over 2 connections, note) | VM |
| a handle created on one thread can be used and closed on another | K/VM |
| EXTENDED_ERROR is readable with a NULL handle from any thread | D `case 0x18` |

## Connectivity
| expectation | tag |
|---|---|
| InternetAttemptConnect(0)=0, any non-zero value gives 87 (as the return value; GetLastError untouched) | D |
| InternetGetConnectedState: flags only use known bits; NULL flags pointer allowed; reserved != 0 gives FALSE/87 with flags zeroed. Lab value: TRUE, 0x12 (LAN \| RAS_INSTALLED) | D; value note |
| InternetGetConnectedStateExW agrees with it; the name is "LAN Connection" on the lab VM (note); ExA = W converted to ACP; the undecorated `InternetGetConnectedStateEx` export is the same function as ExA | D `@0x286e0` (two export names, same RVA) |

## Environment notes
The lab image has ProxyEnable=0, autodetect=1 and SecureProtocols=0x800. PRECONFIG sessions report access type 1
there (note only). The global MAX_CONNS_PER_SERVER is 2 (note).

## Pass 2 (sh_types.c, sh_setrules.c, sh_life.c, sh_flags.c, sh_conc.c)
Boot 1 of pass 2 ran 201 tests: 194 passed as written; the 7 failures were wrong guesses (replaced by the VM value:
OpenUrl(ftp) USERNAME "", InternetWriteFile 6, CONNECT_TIMEOUT 0 ignored), a test bug (a 2 s connect timeout turns a
refused loopback connect into 12002 because Windows retries the SYN for ~2 s) or a note-only fact (FTP QUIT, rare race
error). Boot 2: 202/202 PASS, 4158 checks. Boot 3 confirmed the facts promoted from boot-2 notes. Tags as above.

### Handle types and per-type rules (`sh_types.c`)
| expectation | tag |
|---|---|
| HANDLE_TYPE values: session 1, FTP connect 2, HTTP connect 4, FTP find 5, FTP find HTML 6, FTP file 7, HTTP request 13, file: request 14; A and W agree; len 4; an 8-byte buffer keeps bytes 4..7; 3 bytes -> 122 with 4 | D `InternetQueryOptionA case 9` tag table; VM |
| a SECURE request is type 13 with URL `https://127.0.0.1/sec` (port 0 + SECURE -> 443), REQUEST_FLAGS 8, SECURITY_FLAGS 0 before the handshake, and CERTIFICATE_STRUCT is **answered** (plain-HTTP requests give 12016) | D (URL); VM (flags, cert struct) |
| dwContext is per handle and never inherited; option 10 (old CONTEXT_VALUE) reads the same 8 bytes; setting option 10 gives 12009 | D `case 10/0x2d`; VM (set) |
| InternetOpenUrl(http): hidden HCon parent with CONTEXT_VALUE **0** (the OpenUrl context goes to the request only); REQUEST_FLAGS on the hidden HCon 12018; its USERNAME is "" | VM |
| InternetOpenUrl(`http://u:p@host/`): the hidden connect and the request read USERNAME/PASSWORD from the URL; the URL option drops the userinfo; no Authorization is sent before a 401 | VM |
| file: request (14): REQUEST_FLAGS, URL, USERNAME, PASSWORD, PROXY_USERNAME/PASSWORD, CODEPAGE, READ_BUFFER_SIZE, KEEP_CONNECTION, SECURITY_FLAGS, USER_AGENT, HTTP_DECODING, REQUEST_PRIORITY all give 12018; timeouts are readable (30000) but setting them gives 12018; CONTEXT_VALUE is settable | D (query/set tag lists for 0x17, 0x22, 0x1c, 0x44, 0xc, 2-8); VM |
| file: request: HttpQueryInfo, HttpSendRequest, HttpOpenRequest and InternetConnect on it give 12018; closing the session closes it | D/VM |
| FTP: FCon parent = session, FFnd/FFil parent = FCon, contexts as given; FtpFindFirstFile handles have an **empty** URL option; FtpOpenFile URL is `ftp://127.0.0.1:<port>/hello.txt` | VM |
| InternetOpenUrl(ftp dir/): type 6 (HTML) by default, 5 with INTERNET_FLAG_RAW_DATA; REQUEST_FLAGS 8; URL as given; the hidden FCon closes with it | VM |
| FtpCommand(fExpectResponse=TRUE) returns an FTP **file** handle (7) parented to the FCon, carrying the dwContext | VM |
| InternetOpenUrl(ftp file): type 7, URL as given, USERNAME reads **""** (an explicit anonymous FCon reads "anonymous") | VM |
| FTP handles: timeouts, READ_BUFFER_SIZE and CODEPAGE round-trip; HTTP_DECODING, SECURITY_FLAGS, REQUEST_PRIORITY, USER_AGENT give 12018 | D set case 0x41/0x1f/0x3a/0x29; VM |
| cross-protocol: HttpOpenRequest(FCon), FtpFindFirstFile(HCon or session), FtpGetCurrentDirectory(HCon), InternetReadFile(session or HCon), InternetQueryDataAvailable(session) give 12018; **InternetWriteFile(HCon or session) gives 6**, InternetWriteFile on an unsent GET request gives 12019 | K/D; VM (WriteFile) |

### Set rules (`sh_setrules.c`)
| expectation | tag |
|---|---|
| InternetSetOptionExA/W: dwFlags != 0 -> 87 and nothing is applied; dwFlags 0 forwards to InternetSetOption (same errors: 12010, 12011, 6) | D `InternetSetOptionExA@0x139ba0` |
| read-only list {1, 9, 0xf, 0x11, 0x13, 0x14, 0x16, 0x33, 0x37, 0x38, 0x39, 0x3d, 0x61, 0x93} -> 12011 on every handle type | D |
| {0x10, 0x4e, 0x4f, 0x50} -> 120; 0x36 (CALLBACK_FILTER) -> 50 | D |
| {0xb, 0x34, 0x5b, 0x5c, 0x5d} accepted and ignored; 0x46 / 0x52 accepted with length 4, 12010 otherwise; AUTODIAL_MODE still reads 1 | D |
| option 0 and > 0xc0 -> 12009 for set, with any length | D `param_2 - 1 > 0xbf` |
| PROXY on a session: length must be 24 (else 12010); access other than 0/1/3 -> 87; PROXY with NULL/"" proxy -> 87; access 0 accepted; connect/request -> 12018 before the length check; round-trip reads `lpszProxyBypass = "<proxy> <bypass>"`, size 70 for the test strings | D `case 0x26`; VM (bypass layout) |
| a proxy set on a DIRECT session after InternetOpen is used by requests created afterwards (absolute-form target, Host = origin, REQUEST_FLAGS has VIA_PROXY 4) | D `case 0x17 +0x3bc`; VM |
| REQUEST_PRIORITY: request only (12018 on session/connect), length 4 (12010), any value round-trips, default 0 | D `case 0x3a`; VM (default) |
| ERROR_MASK: any handle; length 4; values with bits outside 0xb -> 87; not queryable (87) | D `case 0x3e`; VM (query) |
| SECURITY_FLAGS on a SECURE request: set ORs `value & 0x13380` into the flags (0 removes nothing, 0xffffffff adds exactly 0x13380); length 2 -> 122, 8 accepted | D `case 0x1f`; VM |
| READ/WRITE_BUFFER_SIZE on HCon/HReq: default 4096, any non-zero value round-trips, 0 -> 87, length 8 -> 12010; on a session 12018 | D `case 0xc/0xd`; VM |
| timeouts on S/C/R: 0, 1, 999, 0x7fffffff, 0xffffffff round-trip, except **CONNECT_TIMEOUT 0 (accepted, value kept)** and **CONNECT_BACKOFF (accepted, always reads 0)**; FROM_CACHE_TIMEOUT default 0xffffffff | D (global 0 rule); VM (handles) |
| BYPASS_EDITED_ENTRY on a handle -> 12018 (12010 first for a bad length) | D `case 0x40` |
| CODEPAGE default 0xffffffff on S/C/R, round-trips, copied to children created later; IDN default 3 on the lab VM (note) | VM |
| HTTP_DECODING stores any DWORD; NULL handle -> 12018 | D/VM |
| NULL handle + PROXY_USERNAME/PROXY_PASSWORD/REQUEST_PRIORITY/SECURITY_FLAGS/READ_BUFFER_SIZE -> 12018 | D `IsPerProcessOption` |
| credentials: the A length is ignored (NUL-terminated); W USERNAME also ignores its length; "" clears; W set on a session -> 12018 | VM |
| USER_AGENT set with W on a session round-trips through A and W | VM |
| CONTEXT_VALUE set after creation is the dwContext of every later callback for that handle, including HANDLE_CLOSING; set to 0 silences them | K, VM |

### Lifetime (`sh_life.c`)
| expectation | tag |
|---|---|
| closing the hidden connect of an InternetOpenUrl request succeeds and invalidates the request | VM |
| two InternetOpenUrl requests get two hidden connects; closing one request closes only its own connect | VM |
| a session with 12 connects x 6 requests: closing it invalidates all 84 children; HANDLE_CLOSING once per child with a context, requests before their connect, none for the zero-context session | D/VM |
| a callback set on a connect reaches requests created under it, not siblings or the session | D (copied at creation); VM |
| SetStatusCallback(h, NULL) returns the previous callback, CALLBACK reads 0, no HANDLE_CLOSING follows; a callback set on the session later does not reach existing children | VM |
| inside HANDLE_CLOSING the handle is already unmapped: queries on it give 6 | D `MapHandleToAddress(h, &obj, 1)`; VM |
| closing the new request inside its own HANDLE_CREATED: the close succeeds and HttpOpenRequest returns NULL with **12017** | VM |
| a request closed with most of a 200000-byte body unread is not drained: each of 3 rounds used a new connection | VM |
| closing a session mid-body ends the server-side connection | VM |
| a failed send (refused port, 12029) leaves the request closable (GLE 0) and the connect usable | VM |
| closing an FTP session invalidates FCon and FFnd (InternetFindNextFile -> 6); QUIT is **not** seen by the server within 3 s (note) | VM |
| handle values are reused immediately (0xcc0004 again after close/open, note); 200 unrelated open/close cycles leave a live tree intact | VM |

### Flags (`sh_flags.c`)
| expectation | tag |
|---|---|
| INTERNET_FLAG_OFFLINE == INTERNET_FLAG_FROM_CACHE == 0x01000000 | K |
| OFFLINE session or FROM_CACHE request, uncached URL: HttpSendRequest / InternetOpenUrl fail with **2** (ERROR_FILE_NOT_FOUND) and nothing reaches the server | D `InitBeginSendRequest uVar5 = 2`; VM |
| an entry cached by a DIRECT session (max-age) is served to an OFFLINE session with no request; REQUEST_FLAGS reads exactly 1 | VM |
| scheme lists: `http=host:port`, `http=http://host:port`, `http=...;ftp=...` and a bare `host:port` proxy http; `ftp=` / `https=` only lists leave http direct | K, VM |
| **127.0.0.1 is never sent to a named proxy**: every bypass list (none, "", `<local>`, a non-matching name, exact IP, wildcards) goes direct | VM |
| the implicit loopback bypass matches the host **string**: `localhost` (any case), `::1`, `[::1]` go direct; `127.0.0.2` and `127.1` go to the proxy (absolute form, VIA_PROXY) | VM |
| `<local>` keeps a dotless host away from the proxy; a dotted name still goes to it | K, VM |
| a proxy session does not affect a DIRECT session in the same process | VM |
| a dead proxy gives 12029 and the request is not retried direct | VM |
| ASYNC session: InternetConnect and HttpOpenRequest return handles synchronously with GLE 0, HANDLE_CREATED on the calling thread, REQUEST_FLAGS 8 | VM |
| INTERNET_FLAG_ASYNC on InternetConnect/HttpOpenRequest of a synchronous session does not make sends asynchronous | D (flag masked); VM |
| FTP connect with INTERNET_FLAG_PASSIVE uses PASV/EPSV, without it PORT/EPRT; FCon REQUEST_FLAGS 12018; the find handle reads 8 either way (no PASSIVE 0x10 bit) | VM |

### Threads (`sh_conc.c`)
| expectation | tag |
|---|---|
| 4 threads closing one handle at once: exactly one TRUE, the others 6 (100 rounds) | D (unmap under the map lock); VM |
| 3 threads querying a request while the session is closed: answers are 13 or 6, nothing else | VM |
| a thread creating connects while the session is closed: creations then fail with 6 (or 12018 if a child reused the freed session value), every created child is closable; a rare other error in the close window is tolerated (note) | VM |
| 8 threads x 100 session/connect/request trees: no failures, kernel handle count unchanged | VM |
| sync callbacks run on the thread that made the call, even for a session created on another thread | K, VM |
| concurrent InternetSetStatusCallback on one handle: every return is NULL or one of the set callbacks; the final CALLBACK is one of them | VM |
| 6 threads setting RECEIVE_TIMEOUT on their own requests under one connect: values never mix; the connect keeps 30000 | VM |
| a request opened on one thread, sent on a second and read and closed on a third | K, VM |
