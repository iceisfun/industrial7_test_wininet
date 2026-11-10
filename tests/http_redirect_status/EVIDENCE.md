# http_redirect_status - evidence for the expectations

Area prefix `rs_`. Every peer is an in-process loopback server started by the test: the "router" in `rs_common.c`
(one `SRV_CALL` step answering each request from a route table, `%P`/`%A`/`%N` templating) or a plain `srv_http` script.
No internet, no proxy/zone/registry change. Cookies use unique paths (`t_uniq`) and are expired at cleanup; cache
entries are registered with `t_cache_track`.

Oracle: Windows 10 22H2 VM (10.0.19045.2965, wininet 11.0.19041.2193), boots `~/w10lab/runs/rs2-20261110-050626-b1`
(first 145 tests, then the area timed out: see "Server teardown" below), `rs3-20261110-061948-b1` (all 318 tests,
2534 checks passed, 15 tests failed and were triaged) and `rs4-*` (after the fixes). Tags:

- **[D]** decomp of the Win10 wininet.dll (docker1 corpus API), function named.
- **[VM]** observed on the Win10 VM and made a hard CHECK (comment `Win10 VM` / `boot rsN` next to the check).
- **[K]** protocol / WinINet knowledge; the VM confirmed every one that is a CHECK.
- Anything still only `t_note` is recorded behaviour, not an expectation.

## Files
| File | Contents |
|---|---|
| `rs_follow.c` | status x method matrix (301/302/303/307/308 x GET/HEAD/POST/PUT/DELETE/OPTIONS/PATCH), 300, missing Location, 304/305/306/309/399, Location forms, other port/host, chains, drain |
| `rs_limits.c` | redirect budget, refused / invalid Locations, NO_AUTO_REDIRECT, 12168 + resend, FORMS_SUBMIT, headers rewritten on a hop, http<->https, option numbers |
| `rs_status.c` | 2xx/4xx/5xx pass-through, status-line parsing, interim 1xx, Retry-After/Refresh/Content-Location ignored, keep-alive after errors, STATUS_CODE query rules |
| `rs_cbcookie.c` | INTERNET_STATUS_REDIRECT (A and W), cookies set by a 3xx, request-header view after a hop, KEEP_CONNECTION, 304 via the URL cache |
| `rs_more.c` | HttpSendRequestEx/HttpEndRequest, W entry points, InternetOpenUrl table, mixed chains, error targets, async mode, option 88/89 probes |

## Redirect decision ([D] `HTTP_REQUEST_HANDLE_OBJECT::HttpSendRequest_Start@0x72da0`)
| Expectation | Evidence |
|---|---|
| Only 300-303, 307, 308 enter the redirect path; 304/305/306/309/399 and Location on 2xx/4xx/5xx are returned as data with the body intact | [D gate `status-300 < 4 \|\| status-0x133 < 2`], [VM] |
| 300 and 308 are only redirected when the response has a Location header (list head of known header 0x21 at `this+0xe38` non-empty); otherwise plain data | [D], [VM] (`rs_follow_300_*`, `rs_follow_308_no_location`) |
| 301/302/303/307 without Location: the body is drained, `Redirect()` fails to find header 0x21 and its **12150 ERROR_HTTP_HEADER_NOT_FOUND** is returned by HttpSendRequest; status still queryable (3xx) | [D Redirect@0x12618 `_FindHeader(0x21)` error path, Redirect_Fsm drains first], [VM rs3] |
| 301/302: GET/HEAD kept, POST -> GET (body and Content-Length/Content-Type dropped), other methods -> **12168** | [D case 0x12d/0x12e: method 2 -> 0, method > 1 -> fsm+0xf8], [VM] |
| 303: every method -> GET (HEAD too) | [D case 0x12f], [VM] (`rs_mixed_head_303_becomes_get`) |
| 307/308: GET/HEAD kept; every other method -> 12168 before any request to the target | [D case 0x133/0x134], [VM] |
| On 12168 `Redirect()` has already run: INTERNET_OPTION_URL is the new URL, one REDIRECT callback; a second HttpSendRequest with the body sends it with the original method | [D DrainAndRedirect before the 0xf8 check], [VM] |
| INTERNET_FLAG_FORMS_SUBMIT (0x40): every followed redirect -> 12168 | [D `0x4f4 & 0x40` -> fsm+0x138], [VM] |
| HttpSendRequestEx + InternetWriteFile + HttpEndRequest: same rules, applied by HttpEndRequest (302/301/303 POST -> GET followed; 307/308 POST and 302 PUT -> 12168 from HttpEndRequest) | [VM rs2] |
| Async (INTERNET_FLAG_ASYNC): ERROR_IO_PENDING, then REQUEST_COMPLETE carries the same results (0, 12168, 12156) | [VM rs2] |
| NO_AUTO_REDIRECT: 3xx is the final response, Location/body/headers readable, one request, no REDIRECT callback | [D `0x4f4 & 0x200000`], [VM] |

## Budget
| Expectation | Evidence |
|---|---|
| **10 redirects**: the 11th 3xx fails with **12156 ERROR_HTTP_REDIRECT_FAILED**; the server sees 11 requests; the 302 (status, Location, headers, body) and the URL of the last hop stay queryable | [D fsm+0x100 from `GlobalMaxHttpRedirects`, `== 0` -> 0x2f7c with fsm+0xf0 = 1], [VM rs2/rs3: 11 requests, sync and async] |
| A chain of exactly 10 redirects succeeds | [VM] (`rs_chain_10`, `rs_chain_11_exceeds_budget`) |
| Each HttpSendRequest gets a fresh budget | [VM] |
| One keep-alive connection for the whole chain when the 3xx bodies are framed | [VM] |
| Option 89 (WinHTTP MAX_HTTP_AUTOMATIC_REDIRECTS number) is accepted on a session but changes nothing (still 11 requests); 88 (WinHTTP REDIRECT_POLICY number) is settable on a request only; neither can be queried (87). WinINet has no redirect-policy or max-redirect option | [VM rs2/rs3] |

## Redirect() ([D `Redirect@0x12618`])
| Expectation | Evidence |
|---|---|
| Only http/https targets (`scheme - 3 > 1` -> 0x2f7c); ftp/file/gopher/mailto/about/unknown schemes: 12156 internally, turned into success by the caller (fsm+0xf0 == 0), so the 3xx is returned **with an empty body** (drained before the check) | [D], [VM rs2/rs3] |
| `javascript:` and `http:///nohost` do not crack: **12005 ERROR_INTERNET_INVALID_URL**, status 302 queryable, URL unchanged | [VM rs3] |
| Relative (`sib`, `../up`, `./here`, `?q`), absolute, protocol-relative, uppercase scheme, no path, padded whitespace resolve as listed in `rs_loc_*`; the fragment is stripped from the request but kept in the REDIRECT callback string | [D PrivateStrChr('#')], [VM] |
| Odd Locations: `""` -> `/`, `/a b` -> `/a%20b`, UTF-8 -> `%C3%A9` on the wire, `\back` -> `/back`, userinfo kept in INTERNET_OPTION_URL but not sent | [VM rs3] |
| First of two Location headers wins; header name case-insensitive | [D index 0 of 0x21], [VM] |
| Host header replaced with the new authority (port included when not 80/443), also over a caller-supplied Host; no duplicate | [D ReplaceHeaderByIndex(0x37)], [VM] |
| If-Modified-Since (header 0x20) always removed on a hop; caller headers (HttpSendRequest and HttpAddRequestHeaders) kept; caller Referer kept for same scheme | [D RemoveAllRequestHeadersByName(0x20)], [VM] |
| The hop request adds `Connection: Keep-Alive` (first request: User-Agent, Host, Cache-Control only) | [VM rs3] |
| https -> http: followed, Referer removed, POST -> GET | [D ReplaceHeaderByIndex(0x23) on scheme change], [VM] |
| http -> https: security flags set on the http request do not cover the hop (IGNORE_REDIRECT_TO_HTTPS neither): 12045, handle already on the https URL; OR-ing IGNORE_UNKNOWN_CA into the same handle and re-sending completes it | [VM rs3] |
| Host change / other port opens a new connection; resolving and connecting callbacks repeat | [VM] |

## Status handling
| Expectation | Evidence |
|---|---|
| Every 2xx/4xx/5xx (incl. 401 with/without challenge under NO_AUTH, 407 without proxy, 408 on a fresh connection, 503+Retry-After, 429) -> HttpSendRequest TRUE, status/text/version/body readable, one request, connection reusable | [D], [VM] |
| STATUS_CODE: string len 3 (A) / 6 bytes (W); FLAG_NUMBER len 4; index 1 -> 12150; short buffers -> 122 with the needed size; REQUEST_HEADERS flag -> 12154; FLAG_NUMBER64 -> 12154 (len stays 8) | [D HttpQueryInfoA case 0x13], [VM] |
| STATUS_CODE before the send succeeds with 0; STATUS_TEXT before the send -> 12150 | [VM rs2/rs3] |
| RETRY_AFTER: string form works; FLAG_NUMBER form -> 12154 | [VM rs2/rs3] |
| Status-line parsing table (`rs_line_*`): custom/empty/missing reason, codes 299/600/999, HTTP/1.0. Odd lines are `t_note` only (`HTTP/1.1 abc` -> status 0xFFFFFFFF, `199` -> 200 synthesized, ...) | [VM] |
| Interim 1xx (100, 102, 103, repeated, with headers, HTTP/1.0) are skipped; one INTERNET_STATUS_INTERMEDIATE_RESPONSE (120) per interim, dword = interim code, len 4; wininet never sends `Expect` itself | [VM] |
| Retry-After / Refresh / Content-Location never trigger a request | [K], [VM] |
| 304 without a cache entry is data; with a cache entry and RESYNCHRONIZE the conditional request carries If-None-Match/If-Modified-Since from the entry and the cached body is returned with status 200 and REQUEST_FLAGS FROM_CACHE | [D GetFromCachePostNetIO for 0x130], [VM] (exact request count is `t_note`, see below) |

## Callbacks and cookies
| Expectation | Evidence |
|---|---|
| INTERNET_STATUS_REDIRECT (110) once per hop with the absolute new URL, after RESPONSE_RECEIVED and before the next SENDING_REQUEST, with the request context; A: length counts the NUL; W: UTF-16 with the length in characters without NUL | [D InternetIndicateStatusString(0x6e)], [VM] (also `async_callbacks` EVIDENCE) |
| No REDIRECT callback for NO_AUTO_REDIRECT, refused schemes, or context 0 | [VM] |
| Set-Cookie on a 3xx is stored before the redirect decision (also for NO_AUTO_REDIRECT and refused Locations) and sent on the hop when path/host match; not sent to another host; nothing stored with NO_COOKIES; COOKIE_RECEIVED/COOKIE_SENT once each | [D ExtractSetCookieHeaders before the switch unless 0x80000], [VM] |
| INTERNET_OPTION_URL: original URL before the send, final URL after (A: len without NUL, 122 gives len+1; W: length in characters) | [VM] |
| INTERNET_OPTION_REQUEST_FLAGS of an unsent request is 0x8 whatever KEEP_CONNECTION/NO_AUTO_REDIRECT | [VM rs3] |

## Environment and test-design notes
- **Server teardown.** wininet keeps idle keep-alive sockets pooled after the handles close and `shutdown()` does not
  wake a blocked `recv`, so with the default 5 s io timeout every `srv_stop` waited out its 3 s join (boot rs2: only 145
  tests in 400 s). The router and `rs_plain()` servers use a 1 s (HTTP) / 2 s (HTTPS) idle timeout.
- **First HTTPS handshake.** In boot rs3 the first HTTPS test of the process (`rs_scheme_https_same_server`) got 12030
  before any request reached the server; every later HTTPS test worked. The test retries once in that exact case and
  notes it.
- Recorded only (`t_note`): the request count of the 304 revalidation and cacheable-301 cases (3 requests where 2 were
  expected; the request lines are logged), odd status lines, Authorization/Cookie supplied by the caller on a hop,
  `INTERNET_OPTION_SECURITY_FLAGS` behaviour on http.
- Knowledge-only and not asserted: zone-crossing warnings 12039/12040/12052 (`GlobalWarnOnZoneCrossing`,
  `GlobalWarnOnHTTPSToHTTPRedirect`) are registry-driven; the lab image does not raise them (https->http is followed).
  Testing them needs a `dx_` area that changes the setting.
