# session_handles: evidence

This area covers InternetOpenA/W, InternetConnectA/W, InternetCloseHandle, handle types, per-handle-type
InternetQueryOption/InternetSetOption rules, status callbacks around handle lifetime, use of handles from
several threads, InternetAttemptConnect and InternetGetConnectedState(Ex). Test names start with `sh_`.

The oracle is genuine Windows 10 22H2 (10.0.19045, wininet 11.0.19041.2193) on the local QEMU guest, run with
`tools/vm_run.sh`. Every hard CHECK passed there. The tags below say where each expectation came from:

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
