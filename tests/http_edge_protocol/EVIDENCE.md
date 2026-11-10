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
(see the per-file comments; summarised after the final boot below)
