# http_edge_protocol: where the expectations come from

Area: protocol robustness of the WinINet HTTP client (wininet.dll 11.0.19041.2193, Windows 10 22H2 19045.2965) against
scripted raw-byte loopback servers (`common/srv.h`). No internet: every request goes to 127.0.0.1/::1; hosts such as
`dp.example`, `bücher.example` or 1000-character names are only used through a PROXY session whose proxy is the
loopback server, so nothing is resolved. Cache and cookies are never touched (`T_INET_FRESH` flags).

Files:
- `hep.h`, `hep_util.c`: servers owning heap scripts, one-request runner, signatures, watchdogs, the keeper session,
  the timing probe (`hep_zz_timing_probe`, runs first).
- `hep_status.c`: status-line table (one TEST per row) + raw-header rebuild + HTTP/0.9 queries.
- `hep_headers.c`: header-block table (obs-fold, NUL/CTL bytes, splitting), Content-Length / Transfer-Encoding
  table, Upgrade/Alt-Svc/HTTP2 advertisements, charsets, long header lines, header counts, tiny TCP segments.
- `hep_conn.c`: keep-alive framing errors, Connection tokens, stale pooled sockets, early close/RST at every stage,
  response before the request body, Expect: 100-continue variants, 1xx interim headers.
- `hep_req.c`: verbs, objects, versions, header-length argument, CR/LF injection through every input, A vs W
  non-ASCII headers, HttpAddRequestHeaders after send, request header sizes/counts.
- `hep_url.c`: long URLs/objects/hosts, fragments, path bytes A/W, CODEPAGE_* and IDN options, IDN hosts, default
  ports, IPv6 literals, userinfo.
- `fill_sigs.py`: freezes `NOTE OBS <tag> | <signature>` lines from a VM result file into the NULL table rows.

Tags: **[D]** decomp of the Win10 binary (Corpus Explorer docker1:8765), **[W10]** observed on the local Win10 VM
(`tools/vm_run.sh`, raw results in `results/win10_hep/`), **[K]** general WinINet knowledge.

## Method
Response-side rows are table-driven: the server sends a raw byte string and closes; the client does one
`HttpOpenRequestA(GET)/HttpSendRequestA/HttpQueryInfoA/InternetReadFile` round; the outcome is folded into a signature
`ok=1 st=<STATUS_CODE|NUMBER> ver=<VERSION> txt=<STATUS_TEXT> [h=<custom header>] [cl=<CONTENT_LENGTH>] n=<bytes> body=<first 48>`
(or `ok=0 err=<GetLastError>`). Every frozen signature was produced by Win10 [W10]; rows still at NULL only print
`NOTE OBS`. Wire-side tests assert on the server recorder (request line, header names in order, raw bytes).

## Decomp sources [D]
| Function | RVA | Used for |
|---|---|---|
| `CHttpHeaderParser::ParseStatusLine` | 0xbd050 | up to 4 junk bytes skipped before a case-insensitive "HTTP"; status = run of ASCII digits, 32-bit accumulate with overflow check (-> invalid response) |
| `HTTP_REQUEST_HANDLE_OBJECT::_ParseResponseLine` | 0xbcea8 | no status line -> downlevel response with a synthetic `HTTP/1.0 200 OK` |
| `InternalHttpOpenRequestA` | 0x8b9b0 | NULL/"" verb -> GET; NULL/"" object -> "/"; NULL/"" version -> `HTTP/%d.%d` (1.1); TRACE/TRACK (case-insensitive, compared over at most 5 chars) -> 12016 |
| `HttpOpenRequestW` | 0xbea10 | object converted with CP_UTF8 |
| `HttpAddRequestHeadersW` | 0x88860 | header text converted with CP_UTF8 |
| `HttpQueryInfoW` | 0x54330 | result converted with the ACP |

## Findings (all [W10] unless tagged)

### Status line (`hep_status.c`) - decomp-explained, VM-frozen
- Any digit run is accepted as the status, without a range check: 600, 699, 999, 1000, 12345 and 4294967295 are
  returned as is; 099 -> 99, 001 -> 1, 0200 -> 200, 42, 7. HttpSendRequest succeeds for all of them.
- The digit run stops at the first non-digit: "200x" -> 200, "2OO" -> 2, "200.5" -> 200, "20 0" -> 20 (text "0 OK").
- No digits (letters, "+200", "-1", "0xC8", full-width or high-bit digits) and an explicit 0/000 -> the numeric
  STATUS_CODE query answers 0xFFFFFFFF (the string form is what the parser kept).
- More than 32 bits ("4294967296", 20 digits) -> HttpSendRequest fails with 12152 (overflow check in ParseStatusLine [D]).
- Up to 4 junk bytes (or leading blanks/CR/LF/NUL) before "HTTP" are skipped; 5 bytes -> the whole response is
  treated as an HTTP/0.9 body. "ICY", "RTSP/1.0", a bare "HTTP", "HTTP/1.1" with no status or an unterminated status
  line + close -> downlevel (`HTTP/1.0 200 OK` synthetic, everything received is body).
- The version token is kept verbatim after "HTTP": `http/1.1`, `HtTp/1.1`, `HTTP/2`, `HTTP/3`, `HTTPS/1.1`, `HTTPX/1.1`,
  `HTTP/` are all accepted and returned by HTTP_QUERY_VERSION.
- Reason phrase: kept verbatim including inner runs of blanks, trailing blanks/TABs, NUL and high bytes; absent reason
  -> "". RAW_HEADERS_CRLF rebuilds the line as `<ver> <code text as received> <reason>` with single spaces
  ("HTTP/1.1 099 X", "HTTP/1.1 200 " for a missing reason).
- Interim 1xx (100, 102, 103, 199) followed by a final status are skipped; 100 then close -> 12152; 101 without an
  Upgrade request is final (st=101, no body read). 204/304 with body bytes: the bytes are readable on a close-framed
  connection. An empty reply (FIN, no byte) -> 12152.
- HTTP/0.9: STATUS_CODE "200", STATUS_TEXT "OK", VERSION "HTTP/1.0", RAW_HEADERS_CRLF "HTTP/1.0 200 OK\r\n\r\n",
  every other header 12150.
- Line endings: LF-only, mixed CRLF/LF and CR CR LF all parse; CR-only lines -> one long status line, no
  Content-Length seen (body empty on that row); LF CR sequences leave a CR in the body.

### Request side (`hep_req.c`)
- Verb: NULL or "" -> GET [D][W10]; TRACE/TRACK (any case, first 5 characters, so also "TRACES") -> 12016 [D][W10];
  leading/trailing blanks trimmed; inner blank, TAB, CR/LF, high byte -> 87. The token is sent exactly as given (no
  case folding) and only the exact upper-case "GET"/"HEAD" are treated as body-less: "get", "head", ... get
  `Content-Length: 0`, and "head" reads the response body.
- Object: NULL/"" -> "/"; a relative name gets a leading "/" ("*" -> "/*", "http://x/y" -> "/http://x/y"); dot
  segments removed, "\" -> "/", TAB/CR/LF removed, space -> %20 (path and query), everything else (including %-escapes,
  invalid ones, "%00", '"<>{}|^`', DEL and high bytes) verbatim; a fragment is sent.
- Version: NULL/""/"HTTP/1.0"/"HTTP/0.9"/non-HTTP token -> "HTTP/1.1"; "HTTP/2.0" and "http/1.1" sent verbatim;
  trailing text or CR/LF after the number -> HttpOpenRequest fails 12153.
- HttpSendRequestA headers: a blank line in the middle or a bare CR -> 12150 and nothing is sent; a bare LF splits
  into two headers; a leading blank on a continuation line just starts a new header (no obs-fold); "Host:" replaces
  the generated Host (in the caller's position); a caller Content-Length goes out verbatim. Headers given to
  HttpSendRequest stay on the handle for the next HttpSendRequest.
- User agent and referrer are cut at the first CR or LF; the referrer is otherwise sent verbatim (space, high byte).
- W entry points: HttpSendRequestW and HttpAddRequestHeadersW put raw UTF-8 on the wire (lone surrogate -> EF BF BD,
  also for a header name); HttpQueryInfoW returns those bytes through the ACP (two characters for "\u00e9");
  non-ASCII W verbs are refused.
- HttpAddRequestHeaders after a send succeeds and applies to the next send, including REPLACE of Host.
- 200 KB header values and 500 added headers go out intact.

### URLs (`hep_url.c`)
- No length limit at INTERNET_MAX_URL_LENGTH: InternetOpenUrlA works and sends the full target for 2083, 2084,
  2085, 4096, 8192, 32768 and 100000-character URLs; HttpOpenRequest objects up to 200000 characters too.
- Host names longer than 256 characters are cut to 256 (Host header and absolute target via proxy); 64-character
  labels are accepted.
- InternetOpenUrl sends the fragment; spaces -> %20; A paths keep high bytes raw; W paths go out as raw UTF-8 for
  both InternetOpenUrlW and HttpOpenRequestW, whatever INTERNET_OPTION_CODEPAGE / CODEPAGE_PATH / CODEPAGE_EXTRA say.
- CODEPAGE options: session defaults 0xFFFFFFFF, IDN default 3; global handle -> 12018; set accepts 0, 65000, 65001,
  437, 932, 1252, 20127, refuses 1, 12345, 0xFFFFFFFF with 87; a 2-byte buffer -> 12010.
- IDN: W host names become punycode (lower case) in the proxy target and Host for every IDN option value 0..3;
  InternetConnectW does the same. A host names are not converted: the target %-escapes the high bytes, Host keeps
  them raw.
- Proxy request form: default port 80 (also ":80", ":080", ":", port 0 / 80 in InternetConnect) is omitted from
  target and Host; ":443" and others kept; the target host is lower-cased, Host keeps the caller's case; an empty
  path becomes "/".
- IPv6: "[::1]" / "::1" / full form, bracketed or not, connect and give a bracketed Host "[::1]:port"; the
  v4-mapped form and a zone id fail 12029; "http://::1:port/" is 12005.
- Userinfo: never pre-emptive; credentials are used on the 401 retry as Basic, %-escapes decoded ("us%40er" ->
  "us@er", "d%5Cu" -> "d\u"); user only / empty user / empty password -> no retry, the caller gets the 401; a second
  ':' -> 12005; userinfo is removed from the Host header and from the proxy target.

### Environment
- Every hep server uses short socket timeouts (HEP_IO_TIMEOUT): WinINet keeps keep-alive sockets pooled after
  InternetCloseHandle, the server thread then sits in recv(), shutdown(SD_BOTH) does not wake it on Windows and
  srv_stop() waited its full 3 s per server (`hep_zz_timing_probe`: 4 stops = 12 s with or without an extra open
  session). This is a property of the shared server library (`common/srv_core.c`), recorded here for the foundation role.
