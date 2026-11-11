# async_callbacks: evidence for the expectations

Area prefix `ac_`. Files: `ac.h`/`ac_util.c` (callback recorder, flow helpers), `ac_setcb.c` (InternetSetStatusCallback,
inheritance, HANDLE_CREATED/HANDLE_CLOSING, CALLBACK/CONTEXT_VALUE options), `ac_send.c` (HttpSendRequest sequences,
sync and async, errors), `ac_read.c` (InternetReadFile / InternetReadFileEx / InternetQueryDataAvailable in async mode,
reads chained inside the callback), `ac_misc.c` (InternetOpenUrl, redirects, cookies, 100-continue, auth, closing with
operations pending, HttpSendRequestEx, FTP, HTTPS), `ac_more.c` (calls made while an operation is pending, contexts and
callbacks changed mid-operation, several requests in flight, status-code / body-size / verb tables, W entry points),
`ac_extra.c` (second pass, prefix `ac_x_`: decomp-grounded parameter checks, calls from inside the callback,
event-driven state machines, closing with read/QDA/ReadFileEx pending, many requests in flight, POST/header/buffer-size
tables, decoding, HEAD/204, redirect chains, InternetOpenUrl redirect/headers/404, sync-session details).

Every peer is an in-process loopback server (`common/srv.h`); no test uses the internet. Sessions are
`INTERNET_OPEN_TYPE_DIRECT`. Async output parameters live in static storage because WinINet writes them from a worker
thread after the call returned 997.

Oracle: Windows 10 22H2 VM (10.0.19045.2965, wininet 11.0.19041.2193), boots `wininet-ac-20261109-171245-b1`
(round 1), `wininet-ac-20261109-173323-b1` (round 2) and the round-3 validation boot (`results/win10/async_callbacks.txt`).

Tags: **[D]** read in the Win10 decompilation (corpus explorer, wininet.dll), **[W10]** observed on the VM (round
number), **[K]** documented/known behaviour only (asserted only where also observed).

## Decomp-grounded [D]

| Fact | Source | Tests |
|---|---|---|
| `InternetSetStatusCallback(NULL, cb)` returns `INTERNET_INVALID_STATUS_CALLBACK` with error 12018 | `InternetSetStatusCallbackCore@0xcef20` (`param_1 == 0 -> 0x2ef2`) | `ac_setcb_null_handle_*` |
| invalid/closed handle: -1 and the MapHandleToAddress error (6) | same | `ac_setcb_garbage_handle`, `ac_setcb_closed_handle` |
| success returns the previous callback and sets last error 0 | same (`SetLastError(dwErrCode)` with 0) | `ac_setcb_first_returns_null_error_zero`, `ac_setcb_returns_previous_chain` |
| the new value is not validated: -1 is stored and returned next time | `RExchangeStatusCallback@0xcefd4` | `ac_setcb_invalid_value_stored` |
| any handle type accepts a callback ("Wild" type check) | `RExchangeStatusCallback` `IsValid(0x646c6957)` | `ac_setcb_every_handle_type` |
| `InternetSetStatusCallback` == `InternetSetStatusCallbackA` (same RVA), W is separate | exports at 0xcee20 / 0xceea0 | `ac_setcb_plain_export_is_ansi` |
| no delivery when the callback or the context is 0 | `InternetIndicateStatus@0x5e500` (`pcVar13 != 0 && lVar10 != 0`) | `ac_created_context_zero_silent`, `ac_opt_context_value_zero_silences`, `ac_async_context_zero_request`, `ac_openurl_async_context_zero` |
| the callback gets a copy of the status information (local/heap buffer) | `InternetIndicateStatus` memcpy into `local_148`/HeapAlloc | `ac_callback_info_is_copy` |
| HANDLE_CREATED carries the 8-byte new handle | `InternetIndicateStatusNewHandle@0x13c124` | `ac_created_*` |
| the W wrapper converts only RESOLVING_NAME (10) and REDIRECT (110); HANDLE_CLOSING suppressed only when `GlobalDisableUnicodeHandleClosingCallback` | `UnicodeStatusCallbackWrapper@0x6d3e0` | `ac_async_w_callback_strings`, `ac_redirect_w_callback_url_wide`, `ac_closing_w_callback` |
| `InternetReadFileExA`: `dwStructSize != 0x38` -> 87; completion context is the handle's (thread ctx = handle+0xb8), not the dwContext argument | `InternetReadFileExA@0xa2e20` | `ac_rfex_bad_struct_size`, `ac_rfex_irf_async_pending` |
| `InternetReadFileExW`: NULL buffers or `lpcszHeader != NULL` -> 87 | docs/research/02 6.2 | `ac_rfex_w_header_rejected` |
| option 1 CALLBACK: set -> 12011, NULL handle -> 12018; 16/30 query -> 120 | docs/research/02 7.1/7.2 | `ac_opt_callback_*`, `ac_async_option_queries` |
| CONTEXT_VALUE set needs length 8 (else 12010) | docs/research/02 7.2 | `ac_opt_context_value_set_bad_length` |

## VM-observed [W10]

Status numbers: 20 CONNECTING, 21 CONNECTED, 30 SENDING, 31 SENT, 40 RECEIVING, 41 RECEIVED, 50 CLOSING_CONNECTION,
51 CONNECTION_CLOSED, 60 HANDLE_CREATED, 70 HANDLE_CLOSING, 80 DETECTING_PROXY, 100 REQUEST_COMPLETE, 110 REDIRECT,
120 INTERMEDIATE_RESPONSE, 320 COOKIE_SENT, 321 COOKIE_RECEIVED.

Sequences (all hard-checked):

| Scenario | Sequence | Tests |
|---|---|---|
| async GET, fresh connection to 127.0.0.1 | `80,20,21,30,31,40,41,100` | `ac_async_send_sequence_fresh_connection`, `ac_status_code_table` (20 codes), `ac_w_apis_async` |
| same, kept-alive connection | `80,30,31,40,41,100` | `ac_async_send_keepalive_reuse_sequence` |
| sync GET | `80,20,21,30,31,40,41` (no 100, all on the calling thread) | `ac_sync_send_sequence`, `ac_sync_send_all_on_calling_thread` |
| async InternetOpenUrl | `60,80,20,21,30,31,40,41,100` (60 from the worker) | `ac_openurl_async_sequence`, `ac_openurl_w_async` |
| sync InternetOpenUrl | `60,80,20,21,30,31,40,41` | `ac_openurl_sync_with_callback` |
| redirect, same connection | `80,20,21,30,31,40,41,110,80,30,31,40,41,100` | `ac_redirect_sequence_exact`, `ac_sync_redirect_sequence` (no 100) |
| redirect to another port | `80,20,21,30,31,40,41,110,80,20,21,30,31,40,41,100` | `ac_redirect_cross_port_new_connection` |
| Set-Cookie response | `80,20,21,30,31,40,41,321,100` | `ac_cookie_received_and_sent`, `ac_sync_cookie_received` |
| request sending a cookie (reused conn) | `80,320,30,31,40,41,100` | `ac_cookie_received_and_sent` |
| 100 Continue before the final reply | `80,20,21,30,31,40,41,120,40,41,100` (120 payload DWORD 100) | `ac_intermediate_response_100` |
| connect refused (async / sync) | `80,20,100` (12029) / `80,20` | `ac_async_send_connect_refused`, `ac_sync_connect_refused_events` |
| server closes without reply | `80,20,21,30,31,40,41,50,51,100` (12152) | `ac_async_send_server_closes_without_reply` |
| server resets | 50,51 before 100, dwError 12031 | `ac_async_send_server_resets` |
| close request with send or read pending | `50,51,100,70`; the completion is FALSE/12017 | `ac_close_request_send_pending`, `ac_close_request_read_pending` |
| close session with send pending | `50,51,100,70,70` (request before connect) | `ac_close_session_with_send_pending` |
| InternetOpenUrl refused | `60,80,20,70,100` (internal handle closed before the failure) | `ac_openurl_async_connect_refused` |
| HttpSendRequestEx / InternetWriteFile / HttpEndRequest | `80,20,21,30,31,100` / writes TRUE synchronously / `40,41,100` | `ac_sendex_write_end_async` |
| HTTPS with IGNORE_UNKNOWN_CA | `80,20,21,30,31,40,41,100` (no extra TLS status) | `ac_https_async_sequence` |
| close request after the body was read (keep-alive) | `70` | `ac_async_keepalive_close_statuses` |
| close request whose body was not read | `50,51,70` | `ac_sync_closing_on_calling_thread`, `ac_async_close_unread_response` |
| pending async read | `40,41,100` | `ac_read_pending_statuses` |

Other observations, hard-checked:
- IP literals produce no RESOLVING_NAME / NAME_RESOLVED, but DETECTING_PROXY (80) is raised for every request even on
  a DIRECT session.
- Name resolution statuses are raised only when WinINet actually resolves: the first `localhost` lookup in the process
  reports 10/11, later ones come from WinINet's resolver cache and report nothing. Tests check 10/11 only when present
  (`ac_async_localhost_resolution_sequence`, `ac_sync_localhost_resolution_sequence`, `ac_async_w_callback_strings`).
  FTP connects to 127.0.0.1 did report 10/11 (note only).
- `localhost` connects to `[::1]`; CONNECTING/CONNECTED_TO_SERVER carry `"[::1]"` (len 6) or `"127.0.0.1"` (len 10),
  i.e. narrow strings with the NUL counted. Narrow REDIRECT length also counts the NUL; in the W callback RESOLVING_NAME
  and REDIRECT are UTF-16 with the length in characters without the NUL (9 for `localhost`).
- SENDING_REQUEST, RECEIVING_RESPONSE and DETECTING_PROXY have no information (NULL, 0). REQUEST_SENT is a DWORD equal
  to the request head size (head + body for a POST sent with HttpSendRequest); RESPONSE_RECEIVED is a DWORD byte count.
- HANDLE_CREATED: `hInternet` is the parent handle, info = new handle, length 8, delivered synchronously on the calling
  thread for InternetConnect/HttpOpenRequest (sync and async sessions), on the worker for async InternetOpenUrl.
- HANDLE_CLOSING: `hInternet` and info are the closing handle, length 8; children close before their parent; a session
  (context 0) reports nothing unless a context is set with INTERNET_OPTION_CONTEXT_VALUE. Inside the HANDLE_CLOSING
  callback the handle is already invalid for InternetQueryOption (error 6).
- REQUEST_COMPLETE: length 16 (INTERNET_ASYNC_RESULT); HttpSendRequest -> dwResult TRUE / dwError 0; InternetOpenUrl ->
  dwResult = the new handle, delivered with `hInternet` = the session; async FTP InternetConnect -> NULL + 997 and
  dwResult = the FTP handle.
- Async: HttpSendRequest, HttpSendRequestEx, HttpEndRequest, InternetOpenUrl (even for an unparsable URL, which then
  completes with 12006) and FTP InternetConnect return FALSE/NULL with 997. InternetConnect(HTTP) and HttpOpenRequest
  return the handle at once (last error 0). InternetOpenUrl("") fails synchronously with 87.
- All send-phase statuses of an async request come from a WinINet worker thread; in a synchronous session every status
  is delivered on the calling thread and REQUEST_COMPLETE is never sent.
- Async InternetReadFile: returns TRUE synchronously when enough data is buffered (no REQUEST_COMPLETE); otherwise 997
  and the completion fills the buffer up to its size or the end of the body (5 buffered + 5 late bytes -> one
  completion of 10). Before HttpSendRequest and with a zero-length buffer it returns TRUE with 0 bytes.
- InternetReadFileEx in an async session: IRF_ASYNC, IRF_SYNC and IRF_NO_WAIT all go pending (997) when nothing is
  buffered.
- InternetQueryDataAvailable async: 997, completion dwResult TRUE with **dwError = bytes available**, and the output
  DWORD is written too; reserved dwFlags/dwContext are not validated.
- While a send is pending: HttpQueryInfo, InternetReadFile and InternetQueryDataAvailable fail with 12019; a second
  HttpSendRequest is accepted with 997 (only that return is checked, the rest is noted).
- Changing CONTEXT_VALUE while a send is pending does not change the completion's context; removing the callback while
  pending suppresses the completion; replacing it routes the completion to the new callback.
- COOKIE_RECEIVED carries an `IncomingCookieState` (32 bytes, cSession = cookies set); COOKIE_SENT an
  `OutgoingCookieState` (16 bytes, cSent = 1). Not raised with INTERNET_FLAG_NO_COOKIES.
- A header line without a colon in async HttpSendRequest fails synchronously with 12150 and no status at all.
- After a failed async send, `HTTP_QUERY_STATUS_CODE|FLAG_NUMBER` succeeds and answers 0.
- A truncated Content-Length body ends with the bytes received (5 of 10) and no read error.

## Second pass (`ac_x_*`, rounds 4-6: boots `wininet-ac4-20261110-050925-b1`, `wininet-ac5-20261110-063103-b1`; validation
boot `wininet-ac6-20261110-081813-b1`: 217 tests, 0 failed, 1946 checks, 455 s)

### Decomp-grounded [D]
| Fact | Source | Tests |
|---|---|---|
| `HttpEndRequestA`: `lpBuffersOut != NULL` -> FALSE/87 before the handle is looked at (even a NULL handle gives 87) | `HttpEndRequestA@0xd46c0` | `ac_x_endreq_a_buffersout_rejected`, `ac_x_endreq_a_null_handle` |
| `HttpEndRequestW`: NULL handle -> 6 (checked first), then `lpBuffersOut != NULL` -> 87 | `HttpEndRequestW@0xd88a0` | `ac_x_endreq_w_null_handle`, `ac_x_endreq_w_buffersout_rejected` |
| `HttpSendRequestExA`: `lpBuffersOut != NULL` -> 87; `lpBuffersIn->dwStructSize != 0x38` -> 87; otherwise lpvBuffer/dwBufferLength/dwBufferTotal go to `HttpWrapSendRequest(...,0x11)` | `HttpSendRequestExA@0xd7f30` | `ac_x_sendex_buffersout_rejected`, `ac_x_sendex_bad_struct_size`, `ac_x_sendex_initial_buffer` |
| `InternetQueryDataAvailable`: valid handle with `lpdwNumberOfBytesAvailable == NULL` -> 87 | `InternetQueryDataAvailable@0x76b20` | `ac_x_qda_null_out_param` |
| No events and nothing on the wire for those parameter failures | same (failure before any FSM is created) | same |

### VM-observed [W10]
| Scenario | Observation | Tests |
|---|---|---|
| POST body via HttpSendRequest, <= 512 bytes | one 30/31 pair, REQUEST_SENT = head + body | `ac_x_post_size_table_request_sent` |
| POST body >= 999 bytes | body sent separately: `20,21,30,31,30,31,40,41,100`, REQUEST_SENT = head, then = body (threshold in 513..998, not asserted) | same |
| extra headers in HttpSendRequest | REQUEST_SENT = bytes of the head on the wire | `ac_x_header_table_request_sent` |
| 6 requests in flight on one connect | 2 connections to the server; a request waiting for a connection while both hold unread responses fails after the 5 s timeout with 12002 and statuses `60,80,100` (round 4); draining each response as it completes lets all six complete | `ac_x_many_requests_distinct_contexts` |
| close connect handle with send pending | `50,51,100,70(req),70(con)`, completion FALSE/12017 | `ac_x_close_connect_with_send_pending` |
| close request with QDA or ReadFileEx(IRF_ASYNC) pending | `50,51,100,70`, completion FALSE/12017 on the request context (not the ReadFileEx dwContext) | `ac_x_close_request_qda_pending`, `ac_x_close_request_rfex_pending` |
| close session with read pending | `50,51,100,70,70`, request before connect | `ac_x_close_session_read_pending` |
| InternetCloseHandle inside REQUEST_COMPLETE | TRUE; HANDLE_CLOSING follows the completion | `ac_x_reentrant_close_in_complete` |
| HttpQueryInfo / QDA / InternetQueryOption(CONTEXT_VALUE) inside the callback | work; the handle's context equals dwContext for every send status | `ac_x_reentrant_*` |
| InternetSetStatusCallback inside the callback | returns the previous callback; replacing in REQUEST_SENT routes `40,41,100` to the new one; removing in REQUEST_COMPLETE silences the request | `ac_x_reentrant_replace_callback_mid_send`, `ac_x_reentrant_remove_callback_in_complete` |
| HttpSendRequest of another request from inside a completion | FALSE/997, completes normally | `ac_x_reentrant_send_other_request` |
| event-driven state machine (reads chained from the callback) | buffered, trickled, chunked, close-delimited, empty and 404 bodies read exactly; a reset gives one completion FALSE/12031 | `ac_x_sm_*` |
| buffered body, any buffer size 1..65536 | every read returns synchronously (3000 bytes in 1-byte reads = 3001 sync reads, no completion) | `ac_x_read_bufsize_table` |
| repeated reads after EOF, HEAD, 204 | TRUE with 0 bytes, synchronously, no REQUEST_COMPLETE | `ac_x_read_after_eof_repeated`, `ac_x_head_read_zero_sync`, `ac_x_204_read_zero_sync` |
| QDA pending then read of that many bytes | completion dwError = 7 = *lpdw; the read returns synchronously | `ac_x_qda_then_exact_read` |
| QDA with the body buffered | synchronous TRUE with the full buffered size (1..1000) | `ac_x_qda_buffered_table` |
| gzip with INTERNET_OPTION_HTTP_DECODING | decoded 900 bytes; without the option the raw gzip bytes | `ac_x_gzip_decoding_async`, `ac_x_gzip_no_decoding_raw` |
| 3 chained 302s | three 110s, each with the absolute next URL, one REQUEST_COMPLETE | `ac_x_redirect_chain_three` |
| POST -> 303 | follow-up is `GET /see` without a body | `ac_x_redirect_303_post_to_get` |
| async InternetOpenUrl + 302 | `60,80,20,21,30,31,40,41,110,80,30,31,40,41,100`; INTERNET_OPTION_URL is the final URL; a 404 still completes with a handle | `ac_x_openurl_async_*` |
| HttpSendRequestEx with an initial buffer | lpvBuffer is sent first, Content-Length = dwBufferTotal | `ac_x_sendex_initial_buffer` |
| 100000-byte InternetWriteFile in an async session | TRUE synchronously, wr = 100000 | `ac_x_sendex_large_write` (noted, accepts 997 too) |
| sync session, late body | InternetReadFile reports `40,41` on the calling thread; ReadFileEx(IRF_ASYNC) is synchronous | `ac_x_sync_late_body_statuses`, `ac_x_sync_rfex_irf_async` |
| callback set on the session after the connect handle was created | neither that connect's requests nor itself report; a new connect handle and its requests do | `ac_x_session_cb_after_request_open` |
| HttpSendRequest / InternetReadFile on a connect handle (async session) | FALSE/12018 synchronously, no status | `ac_x_send_on_connect_handle`, `ac_x_read_on_connect_handle` |
| InternetQueryDataAvailable on a connect handle (async session) | FALSE/997, then one REQUEST_COMPLETE (failure noted); nothing sent | `ac_x_qda_on_connect_handle` |
| InternetQueryDataAvailable(NULL handle), HttpEndRequestA(NULL handle) | FALSE/6 (QDA output untouched) | `ac_x_qda_null_handle`, `ac_x_endreq_a_null_handle` |
| HttpEndRequest on a request never started with HttpSendRequestEx | FALSE/997, then only `100` with FALSE/12017; nothing on the wire | `ac_x_endreq_without_sendex` |
| W callback on one request | REDIRECT wide, CONNECTING_TO_SERVER narrow | `ac_x_w_and_a_on_sibling_requests` |
| InternetConnect(HTTP) x4 | only HANDLE_CREATED on the calling thread, no connection opened | `ac_x_connect_http_no_complete` |
| Set-Cookie with INTERNET_FLAG_NO_COOKIES | no 320/321 | `ac_x_status_values_documented` |

Round-3/4/5 corrections to earlier tests:
- `ac_pending_second_send`: a second HttpSendRequest while the first is pending returns FALSE/997, but the process later died
  with STATUS_HEAP_CORRUPTION (0xc0000374, round 3). The probe now runs in a child process that terminates itself right
  after the call and reports the return in its exit code.
- `ac_openurl_async_sequence`: on some boots (rounds 3 and 5) InternetOpenUrl to `127.0.0.1` reported `10,11` after `80`; both forms accepted.
- `ac_intermediate_response_100`: the second `40,41` after 120 is segmentation dependent; both forms accepted.

## Noted only (variable or not understood; `t_note`)
- A 1 s INTERNET_OPTION_RECEIVE_TIMEOUT on the request did not cut short a 3 s server delay in async mode (completed 200).
- HTTPS with an untrusted certificate in async mode: round 2 completed in 31 ms with 12045 (`80,20,21,50,51,100`);
  round 1 did not complete within 8 s. Recorded by `ac_https_async_cert_error_probe` only.
- Second HttpSendRequest while pending (round 2): first completion reported failure, two requests reached the server.
- 401 with credentials sequence (`80,20,21,30,31,40,41,40,41,80,30,31,40,41,100`), FTP connect sequence, number of
  pending reads for chunked/large bodies, RESPONSE_RECEIVED byte counts (segmentation dependent).

## Knowledge-only [K] (not asserted beyond what the VM confirmed)
- Child handles inherit the parent's callback at creation (confirmed [W10]: `ac_setcb_*inherit*`).
- INTERNET_STATUS_CTL_RESPONSE_RECEIVED (42), PREFETCH (43), STATE_CHANGE (200), USER_INPUT_REQUIRED (140), P3P (325/326),
  COOKIE_HISTORY (327), PRIVACY_IMPACTED (324) and 330 (0x14a): never observed in these scenarios; no test asserts them.

## Environment
Guest has no internet, firewall/Defender as installed; nothing interfered with loopback. `autodetect=1` in the
per-user settings does not matter for DIRECT sessions, but DETECTING_PROXY (80) is still reported per request.

## Triage 2026-11-11 (Win10 22H2 VM, tri-async_callbacks runs)
- `ac_y_reentrant_read_in_request_sent`: Win10 returns TRUE/err 0 for InternetReadFile issued inside REQUEST_SENT
  (not 12019). Hard checks on ret/err removed (result stays in t_note); `fired==1`, send ok, one REQUEST_COMPLETE kept.
  Cause: wrong expectation.
- `ac_sequential_requests_reuse_table`: in one boot iterations k=2 and k=6 lacked the trailing read-side `40,41` pair
  (seq `80,30,31,40,41,100`). Timing/segmentation dependent; both forms now accepted. Cause: timing-dependent expectation.
