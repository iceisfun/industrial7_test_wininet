# cookies: where the expectations come from

Area `cookies` (prefix `ck_`), files `ck_api.c`, `ck_parse.c`, `ck_match.c`, `ck_wire.c`, `ck_extra.c`, `ck_ex2set.c`,
`ck_more.c`, `ck_wire2.c`, helpers
`ck.h` / `ck_util.c`. Oracle: Windows 10 22H2 VM (wininet.dll 11.0.19041.2193). Decomp: Win10 reference corpus
(`/api/function/wininet/<fn>/decomp`).

Status: Win10 22H2 VM boot 4 (ckb4-20261110-082152): PASS, 326 tests, 0 failed, 162 s.

Labels: **D** = read in the decomp, **VM** = observed on the Win10 VM (and asserted), **D+VM** = both,
**K** = general WinINet knowledge, checked on the VM before becoming a CHECK. Anything still unexplained is a
`t_note`, never a CHECK.

## Harness note
`common/t.h` `EXPECT_EQ(a, b)` evaluates `a` twice (once to compare, once for the message). In VM boot 1 that
re-ran `HttpSendRequest`, sized `InternetGetCookie` calls and `HttpQueryInfo(index)`. `ck.h` redefines
`EXPECT_EQ`/`EXPECT_NE` with single evaluation for this area. Other areas that pass calls with side effects to
`EXPECT_EQ` are affected the same way.

## API and buffer protocol (`ck_api.c`)
| Expectation | Source |
|---|---|
| NULL url / NULL data -> FALSE (Ex: 0 = COOKIE_STATE_UNKNOWN), GLE 87, for A, W, ExA, ExW | D (InternalInternetSetCookie@0x6a7d0) + VM |
| EVALUATE_P3P together with APPLY_P3P -> 87 | D + VM |
| Successful set: InternetSetCookieA/W return 1, Ex returns COOKIE_STATE_ACCEPT (1), GLE 0 | D (state returned, 5 mapped to 0 by the A wrapper) + VM |
| Expired cookie for a name that does not exist -> TRUE / ACCEPT | D (SetCookieParsed delete branch) + VM |
| GetEx NULL url / NULL size -> 87; *size untouched | D (InternetGetCookieExW@0xbeed0, ExA@0x16a140) + VM |
| ExW lpReserved != NULL -> 87; ExA ignores lpReserved | D (W) + VM (A) |
| No cookie -> FALSE, 259 ERROR_NO_MORE_ITEMS, *size = 0 (also NULL buffer) | D + VM |
| A: NULL buffer -> TRUE, size = strlen + 1; too small (incl. *size 0) -> 122 with size = needed, buffer untouched; success size = bytes incl. NUL | D + VM |
| W: NULL buffer -> TRUE, size in **bytes**; too small -> 122, size in **bytes**; success -> size in **chars** incl. NUL | D + VM |
| InternetGetCookieA ignores the cookie name (passes NULL to ExA); InternetGetCookieW honours it | D (A) + VM (both) |
| Name filter is exact and case-sensitive (lstrcmpA) | D + VM (boot 1 corrected the K guess) |
| W strings converted through the ACP (Latin-1 value round-trips on 1252) | D (WCharToCharHelper / MultiByteToWideChar(0)) + VM |
| "not a url" and "" -> 12006 ERROR_INTERNET_UNRECOGNIZED_SCHEME | VM |
| ftp:// -> 87 (only http, https, file accepted) | D (PathAndRDomainFromURL) + VM |
| host with a character outside `-.0-9:A-Z[]_a-z` -> 87 | D + VM |
| host lower-cased, port ignored, query/fragment ignored, userinfo ignored, http and https share the jar | D + VM |

## Parsing (`ck_parse.c`)
| Expectation | Source |
|---|---|
| name/value trimming (space, tab), first `=` splits, `;` ends the value, no `=` -> nameless cookie returned as bare value, `=v` -> nameless | D (ParseHeader@0x6c760) + VM |
| name param stored as `name=data` | D + VM |
| control characters replaced by `_` | VM (replaceControlChars, D name only) |
| empty data stores an empty nameless cookie; Get returns TRUE, "" with size 1 | VM |
| maximum cookie string 5117 chars (`StringCchCopyA` into 0x13fe), 5118+ -> 122; with a name param the same 5117 total | D + VM (boot 1 corrected the 5119 guess) |
| 4096-byte value and 3000-byte name accepted | VM |
| expires in the past deletes (RFC 1123, RFC 850, asctime forms; attribute name case-insensitive); garbage date -> session | D (FInternalParseHttpDate) + VM |
| `01-Jan-70` (two-digit 70) does not delete (not read as 1970) | VM |
| Max-Age <= 0 deletes (now - 1 day), Max-Age wins over Expires whatever the order, garbage Max-Age ignored | D + VM |
| Ex2 flags: session 0x202, persistent 0x200, secure +0x1, HttpOnly +0x2000, host-only +0x84000, SameSite Strict 0x100000 / Lax 0x200000 / None none | D (bits) + VM (exact values) |
| Ex2: domain is the forward host, path as stored, fExpiresSet / ftExpires (max-age 7200 -> ~7200 s) | VM |
| Ex2 invalid flag mask 0xdfb9efef -> 87; NULL url/out pointers -> 87; ALL_COOKIES needs an empty URL; no cookie -> 0 with count 0 | D + VM |
| SetCookieEx2 basic -> 0, state ACCEPT; NULL state pointer -> 87 | VM |
| HttpOnly attribute without INTERNET_COOKIE_HTTPONLY/NON_SCRIPT -> FALSE / REJECT, GLE 4317 | D + VM |

## Matching (`ck_match.c`)
| Expectation | Source |
|---|---|
| no Domain= -> visible to subdomains (not host-only) unless INTERNET_COOKIE_APPLY_HOST_ONLY | D (0x8000 -> 0x4000) + VM |
| Domain= parent accepted, leading dot equivalent, case-insensitive; unrelated / child / TLD / Domain=localhost -> 87 | D (IsDomainLegal) + VM |
| IP literal: exact host only, Domain=127.0.0.1 accepted, partial IP rejected; localhost and 127.0.0.1 separate; [::1] works | D + VM |
| path match is a plain prefix of the request path cut at its last `/` (`Path=/a` matches `/ab/`, not `/a`) | D (InternalInternetGetCookieEx2 match loop, PathAndRDomainFromURL param 5) + VM |
| default path = URL path up to the last `/` | VM (Ex2 view) |
| Path without leading `/` -> 87; empty Path= matches everything; `?` cuts the path | D (87) + VM |
| order: longer path first; same path in insertion order; replacement keeps position; host cookies before domain cookies | VM |
| names case-sensitive (k and K distinct) | VM |
| Secure cookie: accepted from an http URL, returned for https only | D (no scheme check on set) + VM |
| HttpOnly: overwrite or delete without the flag rejected (4317); NON_SCRIPT overwrite drops HttpOnly | D (SetCookieParsed returns 4) + VM |
| Get with THIRD_PARTY or INTERNET_FLAG_RESTRICTED_ZONE returns nothing (259) under default settings | D (mask 0x461010, zone 4) + VM |
| SAME_SITE_LEVEL_CROSS_SITE get drops Strict and Lax cookies | D + VM |
| 180 cookies per domain (all paths); the 181st evicts the oldest; replacing does not evict | D (EnforceCookieLimits `0xb3 < count`) + VM |
| one jar per process, no session needed; session cookies invisible to a child process, persistent ones visible both ways | K + VM |
| SUPPRESS_BEHAVIOR COOKIE_PERSIST makes new persistent cookies session-only (flags 0x202), RESET restores; bad value 87, short length 12010, query 87 | D (GlobalSuppressCookiePersist) + VM |
| END_BROWSER_SESSION drops session cookies, keeps persistent ones | K + VM |

## Wire (`ck_wire.c`, loopback server)
| Expectation | Source |
|---|---|
| Set-Cookie stored (several headers, last same name wins, header name case-insensitive, comma not split); Set-Cookie2 ignored | D (HTTP_QUERY_SET_COOKIE only) + VM |
| Cookie header `a=1; b=2`, header name `Cookie`, absent when nothing matches; longer path first; nameless cookie sent as bare value | VM |
| HttpOnly from the network stored (needs the flag to read back) and sent; SameSite cookies sent on direct requests | D (param_11 = 1) + VM |
| Secure Set-Cookie over http stored (https-visible), not sent over http; HTTPS request sends it | VM |
| Max-Age=0 / past Expires on the wire delete; bad Path= rejected; Domain=127.0.0.1 accepted, Domain=i7test.example rejected | D + VM |
| INTERNET_FLAG_NO_COOKIES: nothing stored or sent (InternetOpenUrl and HttpOpenRequest), caller's Cookie header kept | D (0x4f4 & 0x80000) + VM |
| caller's Cookie header is replaced by the jar's when the jar has a match | VM |
| Set-Cookie on a 302 stored before following, sent to the target; on a 404 stored | D (ExtractSetCookieHeaders first) + VM |
| HTTP_QUERY_SET_COOKIE with index walks the headers, then 12150; request Cookie header readable with FLAG_REQUEST_HEADERS | VM |
| status callback COOKIE_RECEIVED (321) once per stored response, COOKIE_SENT (320) once per request with cookies | VM |

## Extras (`ck_extra.c`)
| Expectation | Source |
|---|---|
| IsDomainLegalCookieDomainA/W (#116/#117) table, NULL -> FALSE/87; `localhost`/`localhost` is FALSE (single label) | D + VM (boot 2 corrected) |
| InternalInternetGetCookie (#346) returns 259 | D + VM |
| per-site decisions: NULL args 87, unknown host 12004, decisions other than 0/1/5 -> FALSE with GLE 0 and nothing saved; enumerate past end FALSE. Nothing is saved or cleared (ClearAll only checked for existence) | D + VM |
| ExportCookieFile (#109/#111): header line unless appending, `host\tTRUE\tpath\tsecure\t<expiry>\tname\tvalue`, session cookies excluded | D + VM |
| The expiry column is Unix time **+ 363543 s**: export subtracts 0x19dae9064bafa80 instead of the 1601->1970 offset, import adds 0x2b60b04e9 s; consistent round trip | D + VM (boots 2-3: +1d/+2d/+30d/max-age all exported +363543) |
| Import of a line less than ~4.2 days ahead stores an already-expired cookie (invisible); lines written with the skew import with the exact expiry | D + VM (boot 3 probe) |
| ImportCookieFile (#108/#110): 7 tab fields, secure column honoured, does not overwrite an existing cookie, missing file / NULL -> FALSE, comment-only / 6-field file -> FALSE | D + VM |

## Structured set and array get (`ck_ex2set.c`)
| Expectation | Source |
|---|---|
| InternetSetCookieEx2: cookie NULL, name+value both NULL, url NULL -> 87 with *state untouched; state NULL -> 87, nothing stored | D (InternalInternetSetCookieEx2@0xcc77c) + VM |
| call flags: any bit of 0xbff96f8f -> 87 (incl. INTERNET_COOKIE_HTTPONLY, APPLY_P3P); THIRD_PARTY, NON_SCRIPT, APPLY_HOST_ONLY, 0x40000, 0x40000000 accepted | D + VM |
| cookie dwFlags: any bit of 0x7fc79dfc -> 87; SECURE, SESSION, IS_RESTRICTED, HOST_ONLY, HOST_ONLY_APPLIED, STRICT, LAX accepted | D + VM |
| HttpOnly cookie flag without NON_SCRIPT -> 4317, state 5; a live HttpOnly cookie cannot be overwritten without the HttpOnly cookie flag even with NON_SCRIPT | D (param_11 = cookie flag only) + VM |
| fExpiresSet FALSE -> session (0x202) whatever ftExpires holds; TRUE -> persistent 0x200 and ftExpires stored verbatim; past -> delete (ACCEPT) | D + VM |
| Strict+Lax -> Strict; domain field: leading `.` skipped, parent accepted, unrelated/child -> 87 with state 0; path without `/` -> 87; path >= 0x8000 chars -> 87 with state 0; NULL path -> URL directory | D + VM |
| value is not parsed (`a; path=/x/; b` stored verbatim); name NULL -> nameless cookie, read back with pwszName NULL; value NULL -> `n=` | D + VM |
| bad URLs: "not a url" 12006, ftp 87, space in host 12005 (state 0); Get: 12006 / 87 / 12006 for "" | VM |
| array order equals the string order (longer path first, insertion order); name filter exact; THIRD_PARTY get returns 0 items | VM |

## Second pass (`ck_more.c`, `ck_wire2.c`)
| Expectation | Source |
|---|---|
| A buffer sweep: every cap < len+1 -> 122 with size len+1 and buffer untouched, else TRUE size len+1 with nothing written past the NUL; W: same in chars, 122 reports bytes; InternetGetCookieA identical | D + VM |
| Max-Age: `60`, case variants, `max-age = 60` persistent; 0 / negative / `= -5` delete; empty, bare, `abc`, `+60`, `60abc`, `60.5`, `0x10`, `"60"`, `-0`, values >= 2^31 ignored (session) | VM (boot 3); ten-year max-age persistent |
| Expires up to year 2200 accepted and stored exactly (2100-12-31 23:59:59 compared as FILETIME) | VM |
| InternetSetCookieExW with HttpOnly and no flag returns COOKIE_STATE_REJECT with GLE **0** (the W wrapper keeps the error only for state 0); InternetSetCookieW returns FALSE/4317 | D (InternetSetCookieExW@0x33a20) + VM |
| EVALUATE_P3P with or without a P3P header string: ACCEPT, GLE 0 (first party, default policy) | D (EvaluateCookiePolicy) + VM |
| file:///C:/... URLs keep cookies (directory scoped); `host.` (trailing dot) is a separate jar entry from `host` | VM |
| 8 threads x 25 setters (half on one shared host) lose nothing; 100 cookies on the shared host | VM |
| Wire: HttpOpenRequest GET/POST/HEAD send the jar; HEAD response Set-Cookie stored; Set-Cookie stored from chunked, HTTP/1.0, close-delimited, 401 and 500 responses; Expires with a comma inside one header is not split; network SameSite flags 0x100002 / 0x200002 (no IS_RESTRICTED) | VM |
| An empty `Set-Cookie:` header stores an empty nameless cookie (`; real=1`) | VM |
| Cookie is the last request header (User-Agent, Host, Cache-Control, Cookie); NO_COOKIES affects only that request; HttpAddRequestHeaders Cookie is replaced by the jar's | VM |
| Path-scoped cookie sent only on the redirect target; jar survives closing the receiving session | VM |
| Not tested: re-sending on the same request handle (boot 2 hung in close after a re-send) | VM |

## Cleanup
Every cookie goes through `ck_set`/`ck_setx`/`ck_track` and is expired again by `ck_cleanup()` (end of each test
and at exit) with the same path/domain and INTERNET_COOKIE_HTTPONLY. Hosts are `wininet<pid>n<seq><tag>.i7test.example`;
wire cookies use 127.0.0.1 with a unique path. Exported files live in `t_tmpdir()`.

## Triage 2026-11-11 (Win10 VM, tri-cookies-1..5)

- `ck_wire_https_secure_cookie_sent` (ck_wire.c:561-566): cause = env flake / harness fragility, not a cookie behaviour.
  The first HTTPS GET to the loopback schannel server intermittently fails on Win10 with
  `ERROR_INTERNET_CONNECTION_ABORTED` (12030) during the handshake (seen in ~3 of 8 first-GETs across runs; stable
  fails in runs 1-3, passes in run 4, fail-then-retry in run 5). The aborted attempt still consumes server
  connection 0 (the only script carrying Set-Cookie), so the retry's 200 had no `tls=1` and the 4 downstream checks fell over.
  Change: for SRV_HTTPS both connection scripts now send the Set-Cookie; the test retries the first GET once (with a t_note)
  before asserting 200. The cookie-behaviour assertions (secure cookie sent over https, not over http) are unchanged.
  Root cause of the handshake abort is not identified (not flags: tried CK_WIRE_BASE, T_INET_FRESH, 0, RELOAD).
