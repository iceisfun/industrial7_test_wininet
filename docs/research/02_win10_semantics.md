# 02 - Windows 10 wininet.dll semantics (the executable-spec reference)

Role: WIN10 SEMANTICS. What the real Windows 10 x64 `wininet.dll` (11.0.19041.2193, corpus 22H2 build
19041.2965) does for the core API surface, written so a test author can turn each line into a `CHECK` or a
`t_note`. Sources and tags, used on every statement:

| tag | meaning | how much to trust it |
|---|---|---|
| **[D fn@rva]** | read from the corpus decompilation of that function (`/api/function/wininet/<fn or rva>/decomp`) | branch structure is reliable; constants are exact; Ghidra can mislabel argument roles, so a hard CHECK still needs one VM pass |
| **[W10]** | measured on genuine Win10 22H2 by lane G (rows copied in `03_prior_data_and_i7.md` section A, raw rows in `data/`) | ground truth; wins over [D] when they disagree |
| **[K]** | long-standing documented / well-known WinINet behaviour, not re-read in the decomp | write the test, run it on the VM before hard-CHECKing |
| **[VM?]** | open question or a [D]/[W10] disagreement | `t_note` only until the VM settles it |

Error-code names used below (decimal): 6 INVALID_HANDLE, 8 NOT_ENOUGH_MEMORY, 50 NOT_SUPPORTED,
87 INVALID_PARAMETER, 120 CALL_NOT_IMPLEMENTED, 122 INSUFFICIENT_BUFFER, 123 INVALID_NAME, 131 NEGATIVE_SEEK,
160 BAD_ARGUMENTS, 259 NO_MORE_ITEMS, 4317 INVALID_OPERATION (0x10dd), 12002 TIMEOUT, 12004 INTERNAL_ERROR,
12005 INVALID_URL, 12006 UNRECOGNIZED_SCHEME, 12009 INVALID_OPTION, 12010 BAD_OPTION_LENGTH,
12011 OPTION_NOT_SETTABLE, 12012 SHUTDOWN, 12016 INVALID_OPERATION, 12018 INCORRECT_HANDLE_TYPE,
12019 INCORRECT_HANDLE_STATE, 12028 ITEM_NOT_FOUND, 12029 CANNOT_CONNECT, 12030 CONNECTION_ABORTED,
12031 CONNECTION_RESET, 12032 FORCE_RETRY, 12150 HTTP_HEADER_NOT_FOUND, 12151 HTTP_DOWNLEVEL_SERVER,
12152 HTTP_INVALID_SERVER_RESPONSE, 12153 HTTP_INVALID_HEADER, 12154 HTTP_INVALID_QUERY_REQUEST,
12155 HTTP_HEADER_ALREADY_EXISTS, 12156 HTTP_REDIRECT_FAILED, 12168 HTTP_REDIRECT_NEEDS_CONFIRMATION,
12172 INTERNET_NOT_INITIALIZED.

Two corrections to earlier lanes, both settled by the decomp:

* `InternetCrackUrlW` is the documented **4-argument** form `(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTSW)`
  [D InternetCrackUrlW@0x2d690]. The "14-argument form" in industrial7 `WININET-W10-LINK.md` (repeated in
  `03_prior_data_and_i7.md` B) is a misreading of the internal `CrackUrl` helper [D CrackUrl@0x60e70],
  which takes 18 arguments. Tests use the SDK prototype.
* `InternetTimeToSystemTime` does **not** prefill from the clock unconditionally; it fills only the fields a
  short string did not supply (see 9.2) [D FInternalParseHttpDate@0xbd930], which matches [W10] task 65.

---------------------------------------------------------------------------------------------------------

## 0. Architecture facts every test depends on

* **The A functions are the engine; W is a converter.** Almost every W export converts strings and calls the
  A body or an internal `*A` worker: `HttpQueryInfoW -> HttpQueryInfoA`, `InternetQueryOptionW ->
  InternetQueryOptionA` (most options), `InternetSetOptionW -> InternetSetOptionA`, `HttpOpenRequestW ->
  InternalHttpOpenRequestA`, `InternetOpenW -> InternalInternetOpen`, `InternetConnectW -> HttpConnect/FtpConnect`,
  `InternetCrackUrlW -> _InternetCrackUrlA`, `InternetCreateUrlW -> _InternetCreateUrlA`,
  `InternetReadFileExW -> InternetReadFileExA`, `HttpAddRequestHeadersW -> HttpAddRequestHeadersA`
  [D each W body]. Consequence: A and W agree on validation and error codes; they differ only in length units
  (section 0.3) and code pages (0.2).
* **HINTERNET values are small integers, not pointers.** `MapHandleToAddress` computes
  `(h - 0x00CC0004) >> 2` as an index into `MapArray`; anything outside the map, a freed slot, or an
  invalidated object is **6 (ERROR_INVALID_HANDLE)** [D MapHandleToAddress@0x58740]. First handle of a
  process is typically 0x00CC0004 and values step by 4 [D, `t_note` only]. During DLL teardown the code is
  12012 [D same].
* **Handle types are 4-char tags**, checked by `HANDLE_OBJECT::IsValid(type)`; mismatch is **12018**,
  bad signature is **6** [D IsValid@0x588e0]:

  | tag | value | INTERNET_OPTION_HANDLE_TYPE answer [D InternetQueryOptionA case 9] |
  |---|---|---|
  | `Inet` 0x74656e49 | InternetOpen session | 1 INTERNET_HANDLE_TYPE_INTERNET |
  | `FCon` 0x6e6f4346 | FTP connect | 2 CONNECT_FTP |
  | `HCon` 0x6e6f4348 | HTTP connect | 4 CONNECT_HTTP |
  | `FFnd` 0x646e4646 / `FFnH` 0x486e4646 | FTP find / find-as-HTML | 5 / 6 |
  | `FFil` 0x6c694646 / `FFlH` 0x486c4646 | FTP file / file-as-HTML | 7 / 8 |
  | `HReq` 0x71655248 | HTTP request | 13 HTTP_REQUEST |
  | `HRlf` 0x666c5248 | file:// request (InternetOpenUrl on file:) | 14 FILE_REQUEST |
  | `Wild` 0x646c6957 | wildcard used by IsValid callers (any type) | - |

  [W10]: session = 1, connect = 4 (task 64).
* **Last error on success.** `InternalInternetOpen` ends with `SetLastError(dwErrCode)` where the code is 0 on
  success, so `InternetOpen` success leaves GetLastError()==0 [D InternalInternetOpen@0xe0650]. The same
  `SetLastError(0 or err)` epilogue is used by `InternetConnectW`, `HttpQueryInfoA/W`, `InternetQueryOptionA`,
  `InternetCrackUrlW`, `InternetCanonicalizeUrlW`, `InternetCombineUrlW` [D]. Test pattern: `SetLastError(0xdead)`
  before the call, CHECK 0 after success for those APIs only.
* **12172 before init.** Workers that find `GlobalDataInitialized == 0` return 12172
  (`HttpConnect`, `InternalHttpOpenRequestA`, `HttpQueryInfoA`, `InternetSetFilePointer`) [D]. Not reachable from a
  test that called InternetOpen first; do not test.

### 0.1 Code pages

| API | conversion | evidence |
|---|---|---|
| InternetOpenW agent/proxy | CP_ACP with `WC_NO_BEST_FIT_CHARS` (0x400); if the default char was used, redo in UTF-8 | [D InternetOpenW@0x515a0] |
| InternetConnectW user/password | same ACP-then-UTF-8 retry; server name via `HostWCharToCharEx` (IDN aware) | [D InternetConnectW@0xc5a70] |
| HttpOpenRequestW verb, version | ACP-then-UTF-8; **object name: UTF-8 always**; referrer: `UrlWCharToChar` | [D HttpOpenRequestW@0xbea10] |
| HttpOpenRequestW accept types | ACP (`WideCharToMultiByte(0,...)`) | [D same] |
| HttpAddRequestHeadersW | UTF-8 | [D HttpAddRequestHeadersW@0x88860] |
| HttpQueryInfoW result | ACP (`MultiByteToWideChar(0,...)`) | [D HttpQueryInfoW@0x54330] |
| InternetCrackUrlW | UTF-8; if the result conversion fails with 1113 (NO_UNICODE_TRANSLATION) it retries with ACP | [D InternetCrackUrlW] |
| InternetSetCookieExW name/data | ACP; url via `CacheUrlWCharToChar` | [D InternetSetCookieExW@0x33a20] |
| CommitUrlCacheEntryW header blob | UTF-8 | [D CommitUrlCacheEntryW@0xd1820] |

Tests: keep strings ASCII unless the test is about code pages; then `t_note` the bytes the server saw.

### 0.2 Length units (the W quirks)

These are the rules that differ between A and W and that every reimplementation gets wrong:

| API (W) | success: `*lpdwLength` = | ERROR_INSUFFICIENT_BUFFER: `*lpdwLength` = | evidence |
|---|---|---|---|
| HttpQueryInfoW (string result) | **bytes**, excluding NUL | **bytes**, including NUL (= A-required x 2) | [D HttpQueryInfoW], [W10] "OK" -> 4, short -> 122 need 6 |
| HttpQueryInfoA (string) | chars excluding NUL | chars including NUL | [D _CopyValueToBuffer@0x53c08], [W10] "OK" -> 2 / need 3 |
| HttpQueryInfo FLAG_NUMBER / SYSTEMTIME | 4 / 16 (copied raw in W too) | 4 / 16 | [D QueryInfo@0x54770], [W10] |
| InternetQueryOptionW string options (USERNAME, PASSWORD, URL, USER_AGENT, PROXY_USERNAME/PASSWORD, SECONDARY_CACHE_KEY, DATAFILE_NAME...) | **characters**, excluding NUL | **bytes**, including NUL | [D InternetQueryOptionW@0xc5d50] |
| InternetQueryOptionA string | chars excluding NUL | chars including NUL | [D InternetQueryOptionA@0x59730, common copy tail] |
| InternetQueryOption fixed-size | size of the value (4 or 8 or struct) | same | [D] |
| InternetCreateUrlW | **characters** excluding NUL | **bytes** including NUL | [D InternetCreateUrlW@0x607f0 / _InternetCreateUrlA@0x61380] |
| InternetGetLastResponseInfoW | chars excluding NUL | bytes (A-len x 2) | [D InternetGetLastResponseInfoW@0x139060] |
| InternetGetCookieExW / GetCookieW | **characters including NUL** | **bytes** including NUL; NULL data buffer = TRUE with bytes | [D InternetGetCookieExW@0xbeed0] [VM?] |
| InternetCrackUrlW component lengths | chars excluding NUL | chars including NUL (per component) | [D _InternetCrackUrlA@0x2dd88] |

---------------------------------------------------------------------------------------------------------

## 1. InternetOpenA/W

`InternetOpenW(agent, access, proxy, bypass, flags)` [D InternetOpenW@0x515a0 -> InternalInternetOpen@0xe0650 ->
INTERNET_HANDLE_OBJECT::CreateInstance@0x3ce98 -> Initialize@0x387e0]:

* Access type: 0 PRECONFIG, 1 DIRECT, 3 PROXY, 4 PRECONFIG_WITH_NO_AUTOPROXY accepted (`(access & ~4) == 0` or 1 or
  3); anything else **87** [D]. [W10]: 99 -> 87.
* PROXY (3) requires a non-NULL, non-empty proxy string, else **87** [D], [W10] NULL -> 87.
* Agent may be NULL (stored only when non-NULL) [D Initialize], [W10] ok. A NULL/empty agent means **no
  User-Agent header is sent** (section 4) [D InitBeginSendRequest@0x88e20].
* `dwFlags` is stored without validation [D Initialize: `this+0x1d0 = flags`]; `INTERNET_FLAG_ASYNC`
  (0x10000000) is latched separately [D]. No flag value makes InternetOpen fail [D]. `INTERNET_FLAG_OFFLINE`
  (0x01000000) propagates to requests (cache-only, section 3.5) [D InitBeginSendRequest].
* The calling module is recorded (`GetModuleHandleExW(FROM_ADDRESS, return address)`) [D]; no observable effect.
* Success: GetLastError()==0 [D]. Each InternetOpen bumps `GlobalInternetOpenHandleCount` [D Initialize].
* `InternetOpenA` calls the same worker directly [D InternetOpenA@0xa68c0].

Option defaults on a fresh session (query with InternetQueryOption): USER_AGENT returns the string ("" when NULL
was passed) [D case 0x29]; HANDLE_TYPE 1 [W10]; timeouts see 7.2.

## 2. InternetConnectA/W

[D InternetConnectW@0xc5a70, HttpConnect@0x5c250]

* NULL session handle / garbage -> 6 (MapHandleToAddress) [D], [W10] garbage -> 6.
* Parent must be an `Inet` handle, else **12018** [D HttpConnect: `IsValid(0x74656e49)`].
* NULL server name: **87** [D W stub @0xc5c80], [W10] 87.
* Empty server name "": the A worker returns **87** (`*server == 0`) [D HttpConnect], but **InternetConnectW("")
  returns 123 ERROR_INVALID_NAME** [W10] (the W path fails earlier in `HostWCharToCharEx`). Test W with 123, A
  with 87 [VM? for A].
* Service: 1 FTP, 3 HTTP; everything else (including 2 GOPHER) **87** [D `(service-1) & ~2`], [W10] 99 -> 87.
* Port 0 (INTERNET_DEFAULT_PORT): **443 if INTERNET_FLAG_SECURE (0x00800000) is in dwFlags, else 80** [D HttpConnect].
* Empty user name / password strings are treated as NULL [D].
* No network I/O happens in InternetConnect for HTTP [D: object construction only], [W10] "HTTP ok (no connect
  until send)". FTP connects immediately: no listener -> 12029 [W10].
* `INTERNET_FLAG_ASYNC` (0x10000000) in the connect flags is ignored/masked (`flags & 0xdfffffff` keeps everything
  but bit 29; async is inherited from the session) [D HttpConnect `uVar20 = param_6 & 0xdfffffff`] [VM? exact bit].

## 3. HttpOpenRequestA/W

[D HttpOpenRequestW@0xbea10 -> InternalHttpOpenRequestA@0x8b9b0]

### 3.1 Validation, in order

1. Handle -> 6 / 12018 unless an `HCon` handle [D IsValid(0x6e6f4348)], [W10] session handle -> 12018, garbage -> 6.
2. Verb (`lpszVerb`):
   * NULL or "" -> **"GET"** [D].
   * Leading SP/TAB skipped; the token is the run of bytes 0x21..0x7E; trailing LWS allowed and trimmed; any
     other byte after the token (e.g. "GE T", "GET\r\n") -> **87** [D]. A verb that is only blanks -> 87 [D].
   * "TRACE" and "TRACK" (case-insensitive, `CompareStringA(LOCALE_INVARIANT, NORM_IGNORECASE)`) -> **12016**
     unless the `EnableHttpTrace` policy is set [D].
   * Method recognition (for caching/redirect logic) is **case-sensitive** `memcmp` against a 31-entry table
     [D MapHttpRequestMethod@0x1722f0]: "get" is an unknown method (sent as written, never cached).
3. Object name NULL or "" -> **"/"** [D].
4. Version (`lpszVersion`):
   * NULL -> "HTTP/%d.%d" from the global `HttpVersionInfo` (default **HTTP/1.1**) [D], [W10] "HTTP/1.1".
   * "HTTP/x.y" parsed with `ExtractDword`; malformed numbers -> **534 (0x216)** [D] [VM?].
   * A string not starting "HTTP/" is accepted as version 1.0 [D] [VM?].
5. Referrer "" -> treated as NULL [D]; a non-empty referrer becomes the **Referer** request header
   (header index 0x23) [D AddHeaderByIndex(0x23)].
6. Accept types: each non-NULL entry (up to 2000) is added to **Accept** (index 0x18) with
   `COALESCE_WITH_COMMA`, i.e. `{"text/*","image/gif",NULL}` -> `Accept: text/*, image/gif` [D AddHeaderByIndex(0x18,
   ..., 0x40000001)].
7. **Blocked ports**: for an http/https connect handle whose port is one of
   **19, 21, 25, 110, 119, 143, 220, 465, 990, 993, 995** HttpOpenRequest fails with **12005** [D switch on
   `this+0x3a4`]. Port 0 is also in the list but InternetConnect has already replaced 0 with 80/443. Fully
   offline-testable: InternetConnect(127.0.0.1, 25) succeeds, HttpOpenRequest -> 12005.
8. `INTERNET_FLAG_ASYNC` (0x10000000) is stripped from the W call's flags [D `& 0xffffffffefffffff`].

### 3.2 Flags folded in by HttpOpenRequest

* Any method other than GET (index 0) and POST (index 2) - i.e. HEAD, PUT, DELETE, OPTIONS, unknown -
  gets `INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE` (0x84000000) added [D `(method & ~2) != 0`].
  POST responses are cacheable under a secondary cache key [D FreeSecondaryCacheKey users].
* Global cache mode 1 adds `INTERNET_FLAG_RESYNCHRONIZE` (0x800), mode 2 adds RELOAD [D GlobalCacheMode]; default
  mode on a clean VM is 0 [K].
* The request URL is built with `HttpGetUrlString(scheme, host, ..., object, port)`; the scheme is HTTPS when the
  request flags contain SECURE, else HTTP [D]; readable via INTERNET_OPTION_URL (7.3).

### 3.3 Initial request-header state (before HttpSendRequest)

* `HTTP_QUERY_REQUEST_METHOD` (45) answers the verb without needing FLAG_REQUEST_HEADERS [D QueryInfo special
  case 0x2d], [W10] "GET" W len 6.
* `HTTP_QUERY_VERSION|HTTP_QUERY_FLAG_REQUEST_HEADERS` answers the request version [D FUN_1801042c4 case 0x12].

### 3.4 Method enum used internally [D Redirect / HttpSendRequest_Start]

0 GET, 1 HEAD, 2 POST (others > 2). Needed to read 5.2.

### 3.5 Flags table (request flags, what the decomp shows them doing)

| flag | value | effect | evidence |
|---|---|---|---|
| RELOAD | 0x80000000 | skip cache read | [D folded flags], [K] |
| NO_CACHE_WRITE | 0x04000000 | no cache entry written | [K] |
| KEEP_CONNECTION | 0x00400000 | keep-alive (default for HTTP/1.1 anyway) | [K] |
| NO_AUTO_REDIRECT | 0x00200000 | 3xx returned to caller | [D HttpSendRequest_Start `0x4f4 & 0x200000`], [W10] 302 not followed |
| SECURE | 0x00800000 | TLS; default port 443; `Host` omits :443 | [D HttpConnect, InitBeginSendRequest] |
| NO_COOKIES | 0x00080000 | no Cookie header, Set-Cookie not stored | [D HttpSendRequest_Start `0x4f4 & 0x80000` skips ExtractSetCookieHeaders] |
| NO_AUTH | 0x00040000 | 401/407 returned to caller, no auth retry | [D `0x4f4 & 0x40000`] |
| OFFLINE / FROM_CACHE | 0x01000000 | cache only; miss -> ERROR_FILE_NOT_FOUND (2) for GET with no body [D InitBeginSendRequest `uVar5 = 2`] [VM?] |
| IGNORE_CERT_CN_INVALID | 0x00001000 | | [K] |
| IGNORE_CERT_DATE_INVALID | 0x00002000 | | [K] |
| IGNORE_REDIRECT_TO_HTTP/HTTPS | 0x8000 / 0x4000 | | [K] |
| NO_UI | 0x00000200 | no dialogs | [K] |
| RESYNCHRONIZE | 0x00000800 | conditional GET if cached | [K] |

---------------------------------------------------------------------------------------------------------

## 4. HttpSendRequest(Ex) and the bytes on the wire

### 4.1 Header assembly at send time [D HTTP_REQUEST_HANDLE_OBJECT::InitBeginSendRequest@0x88e20]

In this order:

1. Headers passed to HttpSendRequest are added with `HttpAddRequestHeadersA` (ADD|REPLACE semantics [K]).
2. **User-Agent** (index 0x27): the session agent, leading/trailing SP/TAB trimmed, added only if not already
   present (flag 0x10000000 = "add if new") [D]. NULL/empty agent -> no User-Agent line [D].
3. **Host** (index 0x37): `"%s"` when the port is the scheme default (80 for http, 443 for https), else
   `"%s:%d"` [D]; host longer than 0x10C chars -> 87 [D]. A Host header supplied by the caller wins
   (`IsCustomHostHeader`) [D symbol], [K].
4. **Content-Length** (index 5): `"%I32u"` of the optional-data length (HttpSendRequest) or `dwBufferTotal`
   (HttpSendRequestEx); also emitted as `Content-Length: 0` when there is no body and the method is not GET/HEAD
   (method index > 1) [D]. Not emitted for GET/HEAD without body [D].
5. **DNT: 1** only when the global DoNotTrack policy is set (off on a clean VM) [D GlobalDoNotTrack].
6. Cookie header: `CreateCookieHeaderIfNeeded` unless NO_COOKIES [D HttpSendRequest_Start].
7. Authorization / Proxy-Authorization when an auth context exists (section 10) [D AddAuthorizationHeader].
8. Accept-Encoding: added only when decoding is enabled (`INTERNET_OPTION_HTTP_DECODING` = TRUE) via
   `_CheckDecompressionRequestHeaders` [D CreateRequestBuffer@0xc5fec callees]; default FALSE -> **no
   Accept-Encoding** on a plain request [K] [VM? exact value "gzip, deflate"].

Request line: `VERB SP object SP version CRLF` built in `InternalHttpOpenRequestA` (verb\0, object, ' ', version)
[D]. Header serialisation: `CHttpHeaders` keeps insertion order [K]; the wire order observed on Win10 for a plain
GET is the thing to record with the connection-event recorder (`t_note` first, CHECK after one VM pass) [VM?].

What a plain `HttpOpenRequest(GET,"/x",NULL ver,NULL ref,NULL accept,0)` + `HttpSendRequest(NULL,0,NULL,0)` is
expected to put on the wire on Win10 [K, VM? for order and extra headers]:

    GET /x HTTP/1.1
    User-Agent: <agent>
    Host: 127.0.0.1:<port>
    Connection: Keep-Alive        (HTTP/1.1 keep-alive is default; Win10 also may send Cache-Control: no-cache when RELOAD)
    <blank line>

`Accept` absent unless accept types were given [D 3.1.6]. `Cache-Control: no-cache` / `Pragma: no-cache` when
RELOAD is set: [K] [VM?] (Win10 sends `Cache-Control: no-cache` for RELOAD requests that bypass cache).

### 4.2 Header-length parameter (HttpSendRequestA/W lpszHeaders, dwHeadersLength) [W10 task 67]

| case | W | A |
|---|---|---|
| (DWORD)-1 | NUL-terminated, ok | ok |
| exact char count | ok | ok |
| **0 with non-NULL headers** | ok, treated as NUL-terminated | **87** |
| count larger than the string (reads past NUL), e.g. bytes instead of chars | **12150** | [VM?] |
| shorter than the string | the prefix is used; a prefix that cuts a header line in half -> 12150 | same [VM?] |
| NULL headers | ok, nothing added | ok |

### 4.3 HttpSendRequestEx / HttpEndRequest

`HttpSendRequestExW(h, lpBuffersIn, lpBuffersOut, flags, ctx)`: `lpBuffersIn.dwBufferTotal` drives
Content-Length (4.1.4) [D InitBeginSendRequest param_5]; data then goes through InternetWriteFile; HttpEndRequest
reads the response. [K]: lpBuffersOut must be NULL (87 otherwise), dwFlags must be 0 [VM?]. Writing fewer bytes
than dwBufferTotal and calling HttpEndRequest fails [K] [VM?: exact code, likely 12152 or 12030].

### 4.4 Redirects [D HttpSendRequest_Start@0x72da0, Redirect@0x12618, DrainAndRedirect@0x26184]

| status | followed? | method after | notes |
|---|---|---|---|
| 300 | only if a Location header is present | unchanged | [D case 300] |
| 301, 302 | yes | **POST -> GET** (body dropped); GET/HEAD kept; other methods (PUT...) -> **12168** NEEDS_CONFIRMATION | [D case 0x12d/0x12e] |
| 303 | yes | always GET | [D case 0x12f] |
| 307, 308 | yes | unchanged; non-GET/HEAD methods -> **12168** | [D case 0x133/0x134] [VM? for 307 POST] |
| 304 / 200 / 206 / 412 | cache post-processing (`GetFromCachePostNetIO`) | | [D] |

* NO_AUTO_REDIRECT -> the 3xx is the final response [D], [W10].
* Redirect budget exhausted -> **12156 REDIRECT_FAILED** [D `0x2f7c`]; the counter starts at `GlobalMaxHttpRedirects`
  (default 100 [K] [VM?]).
* Set-Cookie on the 3xx response is stored before following (ExtractSetCookieHeaders runs first) [D].
* After a followed redirect, `INTERNET_OPTION_URL` returns the final URL and `HTTP_QUERY_STATUS_CODE` the final
  status; callback INTERNET_STATUS_REDIRECT (110) carries the new URL [K].
* [W10]: 301/302 followed by default; server saw `GET /len10` second (n15 rows).

### 4.5 Status-code driven errors

* HTTP/0.9 (no status line): `HttpQueryInfo` on response headers -> **12151 DOWNLEVEL_SERVER** [D QueryInfo
  `this[0x142c] & 2`]; STATUS_CODE string answers "0" when no status was parsed [D QueryInfo case 0x13].
* 401/407 with NO_AUTH or no credentials: request completes, caller sees 401/407 [K].

---------------------------------------------------------------------------------------------------------

## 5. HttpQueryInfoA/W

[D HttpQueryInfoA@0x54ae0, HttpQueryInfoW@0x54330, HTTP_REQUEST_HANDLE_OBJECT::QueryInfo@0x54770,
CHttpHeaders::_CopyValueToBuffer@0x53c08]

### 5.1 Argument validation (A; W adds its own checks first)

| check | error |
|---|---|
| handle not `HReq` | 6 / 12018 |
| info level (low 26 bits) > 0x5F and != 0xFFFF (CUSTOM) | **87** |
| `lpdwBufferLength == NULL` | **87** ([W10] 87) |
| modifier pairs: REQUEST_HEADERS+COALESCE_WITH_COMMA, NUMBER64+COMMA, NUMBER+NUMBER64, NUMBER+SYSTEMTIME, SYSTEMTIME+NUMBER64, NUMBER+COMMA, SYSTEMTIME+COMMA | **87** |
| `lpdwIndex` non-NULL, `*lpdwIndex != 0`, with COALESCE_WITH_COMMA | **12150** |
| `*lpdwIndex != 0` for VERSION(18)/STATUS_CODE(19)/STATUS_TEXT(20)/RAW_HEADERS(21)/RAW_HEADERS_CRLF(22) | 12150 [D FUN_180104558] [VM?] |
| CUSTOM with NULL buffer | **87** [D], [W10] 87 |
| CUSTOM header name containing a control char or a space | **87**; the name ends at the first `:` / CR / LF (so "X-Test:" == "X-Test") |
| modifier not allowed for that level (per-level mask in `GlobalKnownHeaders`) | **12154** |
| PASSPORT_URLS/PASSPORT_CONFIG (73/74) on the response | 12154 |
| STATUS_CODE or STATUS_TEXT with FLAG_REQUEST_HEADERS | **12154** [D], [W10] 12154 |
| response query before a response exists (`this+0x4f8 & 0x200` clear) | **12019** [D] - **but [W10] task 64 saw STATUS_CODE and RAW_HEADERS_CRLF ok (err 0) on a fresh handle** [VM?] |
| header absent | **12150** [D `0x800c2f76`], [W10] |

W wrapper extra rules [D HttpQueryInfoW]:
* `lpdwBufferLength == NULL` -> 87; `*lpdwBufferLength != 0 && lpBuffer == NULL` -> 87. So `(NULL, &len=0)` is the
  size query: returns FALSE/122 with the required byte count.
* For FLAG_NUMBER (0x20000000) / FLAG_SYSTEMTIME (0x40000000) the data is copied raw and `*len` is the A length.
  **FLAG_NUMBER64 (0x08000000) on a non-CUSTOM level is not in the W raw-copy mask** (0x60000000): the 8-byte
  result is run through MultiByteToWideChar as if it were text [D] - `t_note` only, never CHECK a NUMBER64 W answer.
* CUSTOM with W: name converted to ACP; buffer sized max(caller bytes, name bytes) [D].

### 5.2 Buffer protocol (A)

* String result: buffer >= len+1 -> copy, NUL-terminate, `*len = len` (no NUL), TRUE; else FALSE/122 and
  `*len = len+1` [D _CopyValueToBuffer]. NULL buffer -> `*len` is first set to 0, then the 122 rule applies [D].
* STATUS_CODE|FLAG_NUMBER: `*len = 4` always; < 4 -> 122 [D QueryInfo case 0x13].
* SYSTEMTIME: 16 bytes; 8-byte buffer -> 122 need 16 [W10].
* Index: on success `*lpdwIndex` advances to the next occurrence (for a header that occurs twice: index 0 ->
  first value, index then 1; querying with 1 -> second value, index then 2) [W10 X-Multi].
* Values are returned with leading blanks trimmed ("  42" -> "42") [W10].
* RAW_HEADERS_CRLF = status line + headers + trailing CRLF CRLF [W10]; RAW_HEADERS = NUL-separated, double-NUL
  terminated [K]; both via `QueryFilteredRawHeaders` [D case 0x15/0x16].
* Unparsable date with SYSTEMTIME -> **12154** (not 12153) [W10 task 65]; parsing rules = 9.2.
* REQUEST_HEADERS with RAW_HEADERS_CRLF returns the request block that was (or will be) sent [D FUN_1801042c4].

---------------------------------------------------------------------------------------------------------

## 6. Body reading

### 6.1 InternetReadFile [D InternetReadFile@0xc6f70 -> InternalInternetReadFile]

* Handle types allowed: HReq, FFil, FFnH, FFlH, HRlf; others -> **12018** [D]; garbage/NULL -> 6 [W10].
* `lpdwNumberOfBytesRead == NULL` -> 87; `*read` is zeroed first; `lpBuffer == NULL` -> 87 [D].
* dwNumberOfBytesToRead 0 -> TRUE, 0 bytes [W10].
* EOF: TRUE with 0 bytes, repeatable [W10]. Truncated Content-Length body (server closes early): TRUE with the
  bytes received then TRUE/0 - no error [W10 n15].
* One read may return more than one network segment (20000-byte body in one 30000-byte read) [W10]; tests must
  loop and never CHECK per-call sizes.
* Chunked and close-delimited bodies are de-chunked/terminated transparently [W10 n15]. With chunked transfer
  there is no Content-Length header (CONTENT_LENGTH query -> 12150) [W10].
* Async session: returns FALSE/ERROR_IO_PENDING (997) and completes with INTERNET_STATUS_REQUEST_COMPLETE [K].

### 6.2 InternetReadFileExA/W

W: `lpBuffersOut == NULL` -> 87; `lpBuffersOut->lpcszHeader != NULL` -> 87; otherwise identical to A [D
InternetReadFileExW@0xa2d90]. Flags IRF_ASYNC/IRF_SYNC/IRF_NO_WAIT [K].

### 6.3 InternetQueryDataAvailable

[W10]: before reading = Content-Length (if small enough to be buffered), after EOF = TRUE/0; first QDA on a large
body is between 1 and the total. dwFlags/dwContext must be 0 [K] [VM?]. Never CHECK the exact first value for
bodies larger than one segment.

### 6.4 InternetSetFilePointer [D InternetSetFilePointer@0x138550]

* Only `HReq` handles, else **12018** (returns INVALID_SET_FILE_POINTER 0xFFFFFFFF) [D].
* `lpDistanceToMoveHigh == NULL` and a result above 4 GiB -> 131 [D].
* Seeking needs a cache-backed or fully buffered response (`SetStreamPointer`); a NO_CACHE_WRITE request that
  cannot seek fails [K] [VM? code].

---------------------------------------------------------------------------------------------------------

## 7. InternetQueryOption / InternetSetOption

[D InternetQueryOptionA@0x59730 (switch at `switchD_180059cd7`), InternetQueryOptionW@0xc5d50,
InternetSetOptionA@0x551b0, InternetSetOptionW@0x53e10]

### 7.1 Global rules

Query:
* `lpdwBufferLength == NULL` -> **87** [D], [W10]. `lpBuffer == NULL` -> `*len = 0` first, then the 122 rule [D].
* NULL handle: allowed only for per-process options (`IsPerProcessOption`) plus 15 (ASYNC_ID) and 24
  (EXTENDED_ERROR). Otherwise: option outside 1..0xC0 -> **12009**, inside -> **12018** with `*len = 0` [D].
  [W10]: CALLBACK with NULL handle -> 12018.
* Option outside 1..0xC0 on a real handle -> 87 via the `default:` arm, or 12009 [VM? which one; [W10] 99999 -> 12009
  on set].
* Fixed-size value: `*len < size` or NULL buffer -> **122** and `*len = size`; success -> `*len = size` [D
  common tail `LAB_18005a031`], [W10] CONNECT_TIMEOUT short -> 122 need 4.
* String value: size = strlen+1; success `*len = strlen`; 122 -> `*len = strlen+1` (A). W: see 0.2.
* PASSWORD / PROXY_PASSWORD: the temporary copy is zeroed and freed after the copy [D].

Set:
* `lpBuffer == NULL` or `dwBufferLength == 0` -> **87**, except for buffer-less options 37, 39, 42, 60, 76, 77, 87,
  89, 90, 91, 92, 93, 95, 104, 108, 124, 126, 135, 142, 145, 150, 152, 154, 160, 161, 164, 166, 167, 175, 176, 182,
  184 [D first switch].
* NULL handle: per-process options (and 15, 24) only; else 12009 (outside 1..0xC0) or **12018** [D], [W10]
  CALLBACK on NULL -> 12018 / on session -> 12011.
* Option outside 1..0xC0 -> **12009** [D], [W10].
* Read-only options -> **12011**: 1 CALLBACK, 9 HANDLE_TYPE, 15 ASYNC_ID, 17, 19, 20, 22 KEEP_CONNECTION, 51 IDLE_STATE,
  55, 56, 57 (CONNECT_TIME/SEND/RECEIVE_THROUGHPUT), 61, 97, 147 COMPRESSED_CONTENT_LENGTH [D], [W10] HANDLE_TYPE and
  CALLBACK -> 12011.
* DWORD options demand `dwBufferLength == 4` (timeouts 2-8/63, 62, 64, 65, 68, 72, 73, 74, 81, 86, 100-102, ...); wrong
  length -> **12010** [D `goto LAB_180055572`], [W10] length 2 -> 12010.
* W string options 34 URL, 41 USER_AGENT, 53 SECONDARY_CACHE_KEY, 83 AUTODIAL_CONNECTION, 96 DATAFILE_EXT: `dwBufferLength`
  is in **characters** (0 -> wcslen) [D InternetSetOptionW case 0x22/0x29/0x35/0x53/0x60]; 28/29/43/44 have their own
  W conversion [D].

### 7.2 Option table (query unless noted; types: S=session `Inet`, C=connect `HCon`/`FCon`, R=request `HReq`, F=FTP file/find)

| # | name | valid on | size | notes / errors | evidence |
|---:|---|---|---|---|---|
| 1 | CALLBACK | any handle | 8 | NULL handle -> 12018 (entry rule); set -> 12011 on any handle | [D], [W10] |
| 2-8, 63 | CONNECT_TIMEOUT, RETRIES, BACKOFF, SEND/RECEIVE_TIMEOUT, DATA_SEND/RECEIVE_TIMEOUT, FROM_CACHE_TIMEOUT | NULL (global) or any of S/C/R/F | 4 | set: len!=4 -> 12010; NULL handle sets the global; **CONNECT_TIMEOUT 0 on the global is silently ignored** (TRUE, value unchanged) | [D], [W10] 0 ok |
| 9 | HANDLE_TYPE | any | 4 | values in section 0; set -> 12011 | [D], [W10] |
| 10, 45 | CONTEXT_VALUE | any | 8 | set needs len 8 else 12010 | [D case 0x2d] |
| 12, 13 | READ/WRITE_BUFFER_SIZE | C, R, F | 4 | others 12018; set 0 -> fails | [D] |
| 15, 16, 26, 30, 78 | ASYNC_ID, ASYNC_PRIORITY, OFFLINE_MODE, ASYNC, IDENTITY | - | - | **120** (query); set 16/78/79/80 -> 120 | [D] |
| 21 | PARENT_HANDLE | any | 8 | session -> NULL | [D] |
| 22 | KEEP_CONNECTION | `HCon` only | 4 | others 12018 | [D] [VM? value] |
| 23 | REQUEST_FLAGS | R, F (not S/C) | 4 | bits: 1 FROM_CACHE, 0x80|1 ..., 4, 8, 0x40, 0x100 | [D case 0x17] |
| 24 | EXTENDED_ERROR | NULL ok (per thread) | 4 | last socket error | [D] |
| 27 | CACHE_STREAM_HANDLE | cache-capable | 8 | not cached -> 122-style failure | [D] |
| 28, 29 | USERNAME, PASSWORD | C, R (not NULL, not S, not file) | string | 12018 on S | [D] |
| 31 | SECURITY_FLAGS | R | 4 | set: len < 4 -> **122**; only bits 0x13380 can be added (IGNORE_REVOCATION 0x80, IGNORE_UNKNOWN_CA 0x100, IGNORE_WRONG_USAGE 0x200, IGNORE_CERT_CN_INVALID 0x1000, IGNORE_CERT_DATE_INVALID 0x2000, 0x10000) | [D case 0x1f] |
| 32 | SECURITY_CERTIFICATE_STRUCT | R | 64 (x64 INTERNET_CERTIFICATE_INFO) | non-TLS request -> 12016 [VM?] | [D] |
| 33 | DATAFILE_NAME | R, F, HRlf | string | none -> **12028** | [D] |
| 34 | URL | R, F | string | | [D] |
| 35 | SECURITY_CERTIFICATE | R | string (formatted) | non-TLS -> **12016** | [D] |
| 36 | SECURITY_KEY_BITNESS | R | 4 | non-TLS -> 12016 | [D] |
| 38 | PROXY | NULL (global) or S | INTERNET_PROXY_INFO | C/R -> 12018; 122 with required size | [D], n8 [W10] |
| 40 | VERSION | NULL ok | 8 INTERNET_VERSION_INFO | | [D] |
| 41 | USER_AGENT | S only | string | C -> 12018 (query and set) [W10]; set "" -> **12010** | [D], [W10] |
| 43, 44 | PROXY_USERNAME, PROXY_PASSWORD | C, R | string | S -> 12018 | [D] |
| 50, 82 | CONNECTED_STATE, AUTODIAL_MODE | NULL | 4 | answers 1 | [D] |
| 51, 52 | IDLE_STATE, OFFLINE_SEMANTICS | NULL | 4 | answers 0 | [D] |
| 53 | SECONDARY_CACHE_KEY | R | string | others 12018 | [D] |
| 54, 55, 56, 57, 70 | CALLBACK_FILTER, CONNECT_TIME, SEND/RECEIVE_THROUGHPUT, DISABLE_AUTODIAL | - | - | **50** | [D] |
| 58 | REQUEST_PRIORITY | R | 4 | | [D] |
| 59 | HTTP_VERSION | NULL | 8 HTTP_VERSION_INFO | default 1.1 | [D] |
| 64 | BYPASS_EDITED_ENTRY | NULL | 4 | | [D] |
| 65 | HTTP_DECODING | S, C(HTTP), R | 4 | set needs non-NULL handle of those types; TRUE initialises the decompressor | [D] |
| 66 | (security connection info) | R | 0x2CC | < 0x2CC -> 122 | [D case 0x42] |
| 67 | DIAGNOSTIC_SOCKET_INFO | R | | | [D case 0x43] |
| 68 | CODEPAGE | S, C, R, F | 4 | set: invalid code page -> 87 | [D] |
| 69 | CACHE_TIMESTAMPS | R | exactly 16 | other length -> 122 | [D] |
| 73, 74 | MAX_CONNS_PER_SERVER, PER_1_0_SERVER | NULL (global) or `HCon` | 4 | set 0 -> **160**; clamped to [2, 128]; per-connect without server info -> 12016 | [D] |
| 75 | PER_CONNECTION_OPTION | NULL or S | INTERNET_PER_CONN_OPTION_LIST (>= 0x20) | NULL buffer -> 87; short -> 12010 | [D] |
| 83 | AUTODIAL_CONNECTION | | string | answers "" | [D] |
| 94 | SOCKET_SEND_BUFFER_LENGTH | | 4 | < 4 -> 12010 | [D case 0x5e] |
| 100-102 | CODEPAGE_PATH, CODEPAGE_EXTRA, IDN | S, C, R, F | 4 | | [D] |
| 103 | MAX_CONNS_PER_PROXY | NULL only | 4 | | [D] |
| 105 | SERVER_CERT_CHAIN_CONTEXT | R | 8 | | [D case 0x69] |

Anything not listed: write the probe with `t_note`, then promote. Never set proxy/zone/registry-persisting options
outside a `dx_` area (SAFETY): 38 PROXY, 39 SETTINGS_CHANGED, 37 REFRESH, 75 PER_CONNECTION_OPTION with a NULL handle
change process-wide or per-user state.

---------------------------------------------------------------------------------------------------------

## 8. URL string logic (pure, offline)

### 8.1 InternetCrackUrlA/W [D InternetCrackUrlW@0x2d690, InternetCrackUrlA@0x2d610, _InternetCrackUrlA@0x2dd88,
CrackUrl@0x60e70, GetUrlAddress@0x61d20]

Validation:
* `lpszUrl == NULL` -> 87. A: `lpUrlComponents == NULL` or **`dwStructSize != 0x68`** (sizeof(URL_COMPONENTS) on
  x64) -> 87. **W: dwStructSize is not checked** (W builds its own 0x68 struct) and on success writes
  `dwStructSize = 0x68` back [D] [VM? CHECK this: a W call with dwStructSize 0 succeeds].
* dwFlags: only ICU_DECODE (0x10000000) and ICU_ESCAPE (0x80000000) allowed; any other bit -> 87.
  With either flag set, at least one component buffer (pointer + nonzero length) must be supplied, else 87.
* dwUrlLength: 0 -> strlen; nonzero -> scanned up to the first NUL inside that count.

Component protocol (per component: scheme, host, user, password, path, extra):
* pointer NULL, length 0 -> not wanted.
* pointer NULL, length nonzero -> on return the pointer points INTO the caller's URL string and the length is the
  component length (no NUL). (W: points into the caller's WCHAR string.)
* pointer non-NULL -> on entry its first char is set to NUL; copy if `len < buflen`, `*len = chars` (no NUL);
  otherwise `*len = chars + 1` and the **whole call fails with 122 after every component has been processed**
  (A: memcpy on the fitting ones still happens) [D].
* ICU_DECODE alone: path and extra info are `UrlUnescapeA(..., URL_UNESCAPE_INPLACE)`'d [D].
  ICU_ESCAPE: the URL is decoded in situ before cracking (`DecodeUrlInSitu`) [D CrackUrl flag 8].
* **ExtraInfo split**: only when the caller asked for extra info (`dwExtraInfoLength != 0`) is the path cut at the
  first `?` or `#`; otherwise **lpszUrlPath includes the query and fragment** [D CrackUrl `param_15` only when
  `local_94 != 0`]. The extra info then starts with the `?`/`#`.
* nPort: explicit port parsed as decimal; non-digit -> **12005**; > 65535 -> **12005** [D GetUrlAddress]. No
  explicit port -> default by scheme: FTP 21, HTTP 80, HTTPS 443, everything else 0 [D].
* nScheme: from a 12-entry table matched case-insensitively (`StrCmpNICA`): ftp=1, gopher=2, http=3, https=4,
  file=5, news=6, mailto=7, socks=8, javascript=9, vbscript=10, res=11; others INTERNET_SCHEME_UNKNOWN (-1) [D
  table at 0x1801f3f60, numbering = SDK INTERNET_SCHEME].
* No `:` in the URL -> **12006** [D CrackUrl].
* Hierarchical schemes need `//`; host missing where `RequireHostNameInUrl` says so -> 12005; host with a byte
  < 0x20 -> 12005; `[` without `]` -> 12005; two `:` in the authority (not bracketed) -> 12005 [D GetUrlAddress].
* `user:pass@host`: split at `@` before the first `/`, `\`(file), `?`, `#` [D]. With the
  `DisableUserPswdForHttp` policy a userinfo in http(s) -> 12005 [D] (off by default [K]).
* IPv6 literal: brackets are kept in lpszHostName [D bracket loop keeps `[`] [VM?].
* **file: URLs**: when the caller wants the path, `PathCreateFromUrlW` converts it: `file:///C:/a/b.txt` ->
  path `C:\a\b.txt` [D _InternetCrackUrlA scheme 5 branch].
* res: (scheme 11): host is everything up to the first `/` [D].
* Opaque schemes (mailto, javascript, unknown without `//`): everything after `:` is the path; host/user/pass/port
  empty/0 [D].

### 8.2 InternetCreateUrlA/W [D InternetCreateUrlW@0x607f0, _InternetCreateUrlA@0x61380]

* `lpUrlComponents == NULL`, `dwStructSize != 0x68`, `lpdwUrlLength == NULL` -> 87.
* dwFlags allowed: ICU_ESCAPE 0x80000000, ICU_USERNAME 0x40000000, 0x2000 (ICU_ESCAPE_AUTHORITY); others -> 87.
* NULL buffer -> `*len` zeroed, then size query (122 + required size).
* Scheme: `lpszScheme` if given (its length must be nonzero or the string NUL-terminated); else from nScheme:
  0 (DEFAULT) -> "http", 1..11 -> table name, anything else -> 87 [D].
* Port is written only when it differs from the scheme default (80/443/21) [D]; 0 is never written [VM?].
* A host with two or more `:` that is not already bracketed is emitted in `[...]` [D].
* ICU_ESCAPE_AUTHORITY (0x2000): user/password bytes outside 0x21..0x7E or in the reserved set are `%XX`-escaped
  with **upper-case** hex [D `'7'+nibble`].
* W lengths: see 0.2.

### 8.3 InternetCanonicalizeUrlA/W, InternetCombineUrlA/W [D InternetCanonicalizeUrlW@0xd48a0,
InternetCombineUrlW@0x35a70, ICUHrToWin32Error@0xdbb10]

* Canonicalize: NULL url, NULL buffer, NULL length, or **`*len == 0` -> 87** (no size-query mode).
* Combine: NULL base, NULL relative, or NULL length -> 87; NULL output buffer is allowed (size query through
  shlwapi) [D].
* Both delegate to shlwapi `UrlCanonicalizeW` / `UrlCombineW` with `dwFlags ^ ICU_NO_ENCODE (0x20000000) |
  URL_WININET_COMPATIBILITY (0x80000000)`: i.e. **escaping of unsafe characters is ON by default and
  ICU_NO_ENCODE turns it off** [D].
* HRESULT mapping: E_POINTER (0x80004003, shlwapi's "buffer too small") -> **122**, E_OUTOFMEMORY -> 8, any
  other failure -> **87** [D]. The required length written on 122 is shlwapi's (chars incl. NUL [K] [VM?]).
* Everything else (dot segments, `\` -> `/`, ICU_BROWSER_MODE, ICU_DECODE, ICU_NO_META) is shlwapi behaviour;
  pin it from the VM, not from Wine [VM?].

---------------------------------------------------------------------------------------------------------

## 9. HTTP dates

### 9.1 InternetTimeFromSystemTime(A|W) [D InternetTimeFromSystemTime@0x19ccd0 (= ...A), ...W@0x19ce30]

* A: **`cbTime < 30` -> 122 first** (before any NULL check); then `dwRFC != 0`, NULL systemtime, NULL buffer, or an
  invalid SYSTEMTIME (SystemTimeToFileTime fails) -> 87.
* W: `cbTime < 60` (bytes) -> 122 first; NULL buffer -> 87; rest as A.
* Format `"%s, %02i %s %02i %02i:%02i:%02i GMT"` -> `Sun, 06 Nov 1994 08:49:37 GMT` (29 chars).
* **Day-of-week quirk**: the weekday name comes from the caller's `wDayOfWeek`, *unless* `wDay > 6`, in which
  case the SYSTEMTIME is normalised through FileTime and the real weekday is used [D `if (6 < wDay)`]. So
  `{1994,11,wDOW=0,wDay=6}` prints `Sun, 06 Nov 1994` even though Nov 6 1994 is a Sunday anyway; but
  `{2024,1,wDOW=3,wDay=1}` prints `Wed, 01 Jan 2024` (2024-01-01 is a Monday) - pin on VM [VM?].
* Year printed with `%02i` (4 digits for normal years).

### 9.2 InternetTimeToSystemTime(A|W) [D InternetTimeToSystemTime@0x19cf70, ...W@0x19cfc0,
FInternalParseHttpDate@0xbd930, MapDayMonthToDword@0xbdbe4]

* NULL string, NULL SYSTEMTIME, or `dwReserved != 0` -> 87; parse failure -> **87** (A); W converts with ACP then the
  same.
* Tokeniser: up to 8 fields; digit runs are numbers, letter runs are mapped by `MapDayMonthToDword`
  (case-insensitive on the 2nd/3rd letter; Sun..Sat -> 0..6, Jan..Dec -> 1..12, "GMT"/`G*` -> zone marker), everything
  else is a separator.
* RFC 1123, RFC 850 (`Sunday, 06-Nov-94 ...`) and asctime (`Sun Nov  6 08:49:37 1994`, month before day) all accepted
  [D, W10 task 65].
* 2-digit years: < 80 -> 20xx, otherwise 19xx [D] ([W10]: "94" -> 1994; "Tue, 15 Nov" -> 2000).
* Fewer than 4 fields: time of day from the clock; fewer than 2 fields: the **whole** value is the current UTC time
  [D], [W10] (`"15"`, `""` -> now). Never CHECK clock-filled fields.
* Weekday is taken from the name, not recomputed [D], [W10] (`Wed, 15 Nov 1994` -> dow 3).
* Range check after parsing: dow > 6, day > 31, hour > 23, minute or second > 59 -> failure [D]
  ([W10] `Mon, 32 Feb 2024 25:61:61 GMT` -> error). Month is not range-checked by the parser [D] [VM?].
* A numeric zone (`+0100`) is applied only to the FILETIME path (not to the SYSTEMTIME API result) [D], [W10] "zone ignored".
* An unknown word (not a day/month/GMT) -> failure, unless it is the 7th field after a weekday-first form [D].

---------------------------------------------------------------------------------------------------------

## 10. Authentication

[D AUTHCTX::CreateAuthCtxForScheme@0x17c3b0, AddAuthorizationHeader@0x17b5b8]

* Scheme name from the challenge, compared case-insensitively: "Nego2" is an alias of "Negotiate".
  Implementations: **Basic** -> BASIC_CTX (in-proc), **Digest** -> DIGEST_CTX (in-proc, gets the TLS channel
  binding token when present), **NTLM / Negotiate / Kerberos** -> PLUG_CTX over SSPI (`sspicli`
  InitializeSecurityContext), **Passport1.4** -> PASSPORT_CTX [D].
* Basic over plain http can be disabled by `DisableBasicOverClearChannel` policy [D]; default allowed [K].
* Negotiate is gated by `GlobalEnableNegotiate` [D].
* Credentials: InternetConnect user/password, INTERNET_OPTION_USERNAME/PASSWORD (28/29) on C/R, or a NULL-handle set
  (global creds) [D SetOption case 0x1c/0x1d]. With credentials present and a 401 `WWW-Authenticate: Basic`,
  WinINet re-sends with `Authorization: Basic base64(user:pass)` automatically (unless NO_AUTH) [K].
* Without credentials the 401 is returned to the caller (status 401, body readable) [K].
* 407 + Proxy-Authenticate behaves the same with the proxy credentials (43/44) [K]; not testable without a proxy
  (do not change proxy settings outside dx_).
* NTLM/Negotiate on loopback with no domain: the first leg sends `Authorization: NTLM <type1>` / `Negotiate <token>`
  [K]; assert only the scheme word and that a token exists; never CHECK token bytes.

---------------------------------------------------------------------------------------------------------

## 11. Cookies

### 11.1 InternetSetCookie(Ex)A/W [D InternetSetCookieExW@0x33a20, InternalInternetSetCookie@0x6a7d0]

* NULL url or NULL cookie data -> **87** (Ex returns 0 = COOKIE_STATE_UNKNOWN with GLE 87) [D].
* `INTERNET_COOKIE_EVALUATE_P3P` (0x40) together with `INTERNET_COOKIE_APPLY_P3P` (0x80) -> 87 [D].
* `lpszCookieName` non-NULL -> the data is stored as `name=data` (name capped to 0x13FE bytes) [D]; NULL name -> the
  data must carry `name=value` itself.
* **HttpOnly**: if the cookie string carries the `HttpOnly` attribute and the caller passed neither
  `INTERNET_COOKIE_HTTPONLY` (0x2000) nor `INTERNET_COOKIE_NON_SCRIPT` (0x1000), the cookie is rejected:
  return value 5 (COOKIE_STATE_REJECT) and **GLE 4317 (0x10DD)**; plain `InternetSetCookie` returns FALSE [D].
* Return value of the Ex form: cookie state (1 ACCEPT on success) [D `uVar6 = local_140`], [K].
* Session vs persistent: no `expires=`/`max-age=` -> session cookie (process lifetime, never written to disk); an
  expiry in the future -> persistent; **an expiry in the past deletes the cookie** - use this for cleanup [K].
* URL determines the default domain/path (`PathAndRDomainFromURL`) [D]; `domain=` must domain-match the URL host
  or the cookie is rejected [K].

### 11.2 InternetGetCookie(Ex)A/W [D InternetGetCookieExW@0xbeed0]

* NULL url -> 87; NULL `lpdwSize` -> 87; `lpReserved != NULL` -> 87 [D].
* `INTERNET_COOKIE_HTTPONLY` (0x2000) implies NON_SCRIPT (0x1000); flags are masked to
  `0x461010` before lookup (THIRD_PARTY 0x10, NON_SCRIPT 0x1000, 0x40000, SAME_SITE_LEVEL_CROSS_SITE 0x400000) [D].
  Without HTTPONLY/NON_SCRIPT, **HttpOnly cookies are not returned** [K].
* No matching cookie -> FALSE, **259 ERROR_NO_MORE_ITEMS**, `*lpdwSize = 0` [D].
* Output format `name=value; name2=value2` (separator `"; "`); a nameless cookie contributes just its value [D].
* Size protocol (W): NULL data -> TRUE and `*size = bytes incl NUL`; too small (compared in chars) -> 122,
  `*size = bytes`; success -> `*size = chars incl NUL` [D] [VM? - unusual, pin it].
* `InternetGetCookieW` = `InternetGetCookieExW(url, name, data, size, 0, NULL)` [D].
* Matching [K]: host-only cookies match the exact host; domain cookies match the domain and subdomains; path is
  a prefix match on `/`-boundaries; `secure` cookies only for https URLs; loopback "127.0.0.1" is a host-only
  domain. Use a per-test unique path (`/wininet_<pid>_<n>/`) to stay isolated.

---------------------------------------------------------------------------------------------------------

## 12. URL cache

[D CreateUrlCacheEntryExW@0xd180, CommitUrlCacheEntryW@0xd1820, GetUrlCacheEntryInfoW@0x81b00,
DeleteUrlCacheEntryW@0x21c10, RetrieveUrlCacheEntryFileW@0x1a1c40]

* All W cache APIs reject a NULL URL with 87, refuse while impersonating (`BlockImpersonatingCaller`) and in
  InPrivate mode (`BlockCallsInPrivateModeW`) [D].
* `CreateUrlCacheEntryW(url, expectedSize, ext, fileName[MAX_PATH], 0)`: NULL fileName -> 87; writes the new local
  file path (up to 260 WCHARs) [D]. The file exists afterwards and the caller writes the content [K].
* `CommitUrlCacheEntryW(url, localFile, expire, lastModified, type, header, headerLen, ext, origUrl)`: header blob
  converted to UTF-8; headerLen 0 -> wcslen [D]. Commit of a nonexistent local file fails [K] [VM? code].
* `GetUrlCacheEntryInfoW(url, NULL, &size)` -> FALSE/122 with the required size; missing entry -> **2
  ERROR_FILE_NOT_FOUND** [K] [VM?]; NULL url -> 87 [D].
* `DeleteUrlCacheEntryW`: NULL -> 87; missing entry -> **2** (the code even suppresses the trace for 2) [D].
* `RetrieveUrlCacheEntryFileW(url, info, &size, 0)`: NULL url or NULL size -> 87; non-NULL info with `*size == 0` -> 87;
  `dwReserved != 0` -> 87 [D]; locks the entry until `UnlockUrlCacheEntryFile`.
* Cleanup rule for tests: every entry created gets `DeleteUrlCacheEntryW` at the end, URLs carry `tmpPrefix+pid`.
* HTTP responses are cached unless NO_CACHE_WRITE, a non-GET/POST method, `Cache-Control: no-store`, or HTTPS
  with `DisableCachingOfSSLPages` [D folded flags, IsCacheControlNoStoreHeaderPresent symbol] [K].

---------------------------------------------------------------------------------------------------------

## 13. Status callbacks and async

[D InternetSetStatusCallbackW@0xceea0 -> InternetSetStatusCallbackCore(h, cb, isUnicode=1)]

* `InternetSetStatusCallback(h, cb)` returns the previous callback, NULL the first time, and
  `INTERNET_INVALID_STATUS_CALLBACK` ((INTERNET_STATUS_CALLBACK)-1) on an invalid handle [K].
* Callbacks fire only for operations with a nonzero dwContext [K].
* Child handles inherit the parent's callback at creation [K].
* Synchronous GET to a loopback server, expected order [K] [VM? - record first, CHECK the relative order of the
  stable subset only]:
  `HANDLE_CREATED(60)` (open request), then on send: `RESOLVING_NAME(10)`, `NAME_RESOLVED(11)`,
  `CONNECTING_TO_SERVER(20)`, `CONNECTED_TO_SERVER(21)`, `SENDING_REQUEST(30)`, `REQUEST_SENT(31)`,
  `RECEIVING_RESPONSE(40)`, `RESPONSE_RECEIVED(41)` (possibly repeated), on close `CLOSING_CONNECTION(50)`/
  `CONNECTION_CLOSED(51)` (only when the connection is not kept alive), `HANDLE_CLOSING(70)`.
  Win10 also emits `INTERNET_STATUS_COOKIE_SENT(320)`, `COOKIE_RECEIVED(321)`, `DETECTING_PROXY(80)`,
  `REDIRECT(110)` with the target URL, `INTERMEDIATE_RESPONSE(120)`, `STATE_CHANGE(200)` and
  status 0x14a (330, not named in the mingw headers; raised from HttpSendRequest_Start when a flag at
  request+0x14ec is set) [D InternetIndicateStatus(0x14a)] where applicable.
* Async (INTERNET_FLAG_ASYNC on InternetOpen): HttpSendRequest / InternetReadFile return FALSE with **997
  ERROR_IO_PENDING** and finish with `REQUEST_COMPLETE(100)` whose INTERNET_ASYNC_RESULT carries dwResult/dwError [K].
  Bounded waits only (event + WaitForSingleObject <= few seconds).
* `InternetCloseHandle` on a handle with a callback delivers HANDLE_CLOSING (70) for it and every child [K].

---------------------------------------------------------------------------------------------------------

## 14. Handle lifetime

[D InternetCloseHandle@0x5cd60 -> InternalInternetCloseHandle@0x5b6d0]

* Garbage / already-closed handle -> **6** [D], [W10] second close -> 6, garbage -> 6.
* Closing a parent closes all children (recursive `InternalInternetCloseHandle` over the child list) [D]: after
  closing the session, a request handle from it is invalid (any call -> 6) [K] [VM?].
* A closed handle value is not immediately reused while references are outstanding [D refcount at +0x8c]; handle
  values may be reused later - never CHECK reuse either way.
* Closing a request with an async operation pending aborts it; the pending operation completes with
  `ERROR_INTERNET_OPERATION_CANCELLED` (12017) [K] [VM?].
* Calls on a handle that is being closed by another thread: 12017 or 6 [K]; do not test (timing).

---------------------------------------------------------------------------------------------------------

## 15. Last-response info, errors, connectivity

* `InternetGetLastResponseInfoW(&err, buf, &len)`: NULL buffer = size query; W length rules in 0.2; after HTTP
  calls it is typically empty (FTP fills it with the server reply text) [D InternetGetLastResponseInfoW] [K].
* `InternetAttemptConnect(0)` -> 0 (ERROR_SUCCESS); any nonzero dwReserved -> 87 (return value is the DWORD error,
  not a BOOL) [D InternetAttemptConnect@0x1378d0].
* `InternetGetConnectedState(&flags, 0)` = `InternetGetConnectedStateExW(&flags, NULL, 0, reserved)`;
  `dwReserved != 0` -> FALSE/87; flags are zeroed then set from RAS/LAN detection (0x10 RAS_INSTALLED, 0x02 LAN,
  0x01 MODEM, 0x04 PROXY, 0x40 CONFIGURED); on success SetLastError(0) [D InternetGetConnectedStateExW@0xd8340].
  Value depends on the VM's network: `t_note` only.
* `InternetCheckConnection`: probes the network; not testable offline beyond argument checks [K].
* WinINet error text: `FormatMessage(FORMAT_MESSAGE_FROM_HMODULE, hWininet, 12xxx)` returns a message for the
  12001..12175 range [K]; OK to CHECK non-empty.
* `InternetErrorDlg`: only with `FLAGS_ERROR_UI_FLAGS_NO_UI`, or not at all (SAFETY).

---------------------------------------------------------------------------------------------------------

## 16. Disagreements / open items for the VM pass

| # | item | [D] says | [W10] says / status |
|---|---|---|---|
| 1 | HttpQueryInfo STATUS_CODE / RAW_HEADERS_CRLF on a request never sent | 12019 (response flag 0x200 not set) | ok, err 0 (task 64) - re-measure, the probe may have sent first |
| 2 | InternetReadFile on a never-sent request | reaches `AttemptReadFromFile` | ok 0 bytes |
| 3 | InternetConnectA("") | 87 | W gives 123; A unmeasured |
| 4 | EXPIRES\|SYSTEMTIME | table-driven like LAST_MODIFIED | 12154 for every variant (task 65) - re-measure |
| 5 | InternetCrackUrlW with dwStructSize 0 | succeeds, writes 0x68 back | unmeasured |
| 6 | Cookie W size units | success = chars incl NUL, 122 = bytes | unmeasured |
| 7 | 307 + POST redirect | 12168 | unmeasured |
| 8 | Default request headers and their order | User-Agent, Host from InitBeginSendRequest; Connection/Cache-Control from [K] | record with the connection-event recorder |
| 9 | Blocked HTTP ports list | 19,21,25,110,119,143,220,465,990,993,995 -> 12005 at HttpOpenRequest | unmeasured, offline, cheap |
| 10 | TRACE/TRACK verbs | 12016 | unmeasured, offline |
| 11 | QueryOption unknown option on a real handle | `default:` -> 87 | set gave 12009; query unmeasured |
| 12 | HttpQueryInfoW + FLAG_NUMBER64 | garbled (string path) | never CHECK |

Promote each row to a hard CHECK only after the Win10 VM agrees; otherwise downgrade to `t_note` with the observed
value and cite this table row.
