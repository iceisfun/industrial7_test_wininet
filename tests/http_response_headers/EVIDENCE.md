# http_response_headers: where the expectations come from

Area: response parsing and `HttpQueryInfoA/W` (wininet.dll 11.0.19041.2193 on Windows 10 22H2 19045.2965).
Files: `rh.h`/`rh_util.c` (helpers + the known-header table), `hqi_args.c`, `hqi_buffer.c`, `hqi_levels.c`,
`hqi_index.c`, `hqi_numdate.c`, `rsp_status.c`, `rsp_headers.c`, and from the second pass `rsp_segments.c`,
`rsp_lifecycle.c`, `hqi_generated.c`, `hqi_reqside.c`, `rsp_values.c` (173 TESTs, about 43000 CHECKs on the VM). Every test runs its own raw-byte loopback server
(`common/srv.h`) on 127.0.0.1. No internet is used, no proxy, cache or zone settings are touched, and cookies are never
stored (`INTERNET_FLAG_NO_COOKIES`).

Tags:
- **[D]**: read from the decomp of the Win10 binary (Corpus Explorer, docker1:8765).
- **[W10]**: observed on the local Win10 VM (`tools/vm_run.sh`; the result file is `results/win10/http_response_headers.txt`).
- **[K]**: general WinINet knowledge.

Every hard CHECK passed on the VM. When the decomp and the VM disagreed, the VM value is the one checked, and the
disagreement is listed below.

## Decomp sources [D]
| Function | RVA | Used for |
|---|---|---|
| `HttpQueryInfoA` | 0x54ae0 | order of the argument checks, the modifier-pair table, the index rules, CUSTOM name validation, the mask check, and NULL buffer -> `*len = 0` |
| `HttpQueryInfoW` | 0x54330 | len/buffer checks done first, widening in place, 2*(n+1) sizing, the raw-copy mask (0x60000000; 0x68000000 on the CUSTOM path) |
| `HTTP_REQUEST_HANDLE_OBJECT::QueryInfo` | 0x54770 | special levels 18/19/20/21/22/45/73/74, and STATUS_CODE falling back to "0" |
| `CHttpHeaders::_FindHeader` | 0xbad40 | lookup by index, the index incremented only on success, NUMBER/NUMBER64/SYSTEMTIME conversion and sizes, and the 128-byte date limit (12004) |
| `_CopyValueToBuffer` | 0x53c08 | string protocol: `*len = n` on success, `n + 1` on a 122 |
| `_FormatAsDword` / `_FormatAsUlonglong` | 0x66138 / 0x661a4 | number parsing: a non-digit ends the number, an empty value gives 12154, overflow gives 534, more than 32 bits gives 12153 |
| `_QueryCoalescedKnownHeader` / `_QueryCoalescedCustomHeader` | 0x173378 / 0x172fb0 | the ", " join and its sizes |
| `QueryFilteredRawHeaders` | 0xbb3e0 | the RAW_HEADERS(_CRLF) layout is rebuilt as `Name: value` + a NUL or CRLF separator, with a double NUL or blank line at the end |
| `GlobalKnownHeaders` table | 0x1f3660 (bytes from the image) | the name and modifier mask of each level, copied into `rh_known[]` |
| `ParseStatusLine` / `ParseHeaders` | 0xbd050 / 0x8a150 | what to probe (scan for "HTTP", status token, NUL/high-bit flags) |

### Facts that are both decomp-grounded and VM-confirmed
- Check order (A): handle (6 / 12018), then level > 0x5F (87), NULL len (87), illegal modifier pairs (87)
  (REQ+COMMA, NUMBER64+COMMA, NUMBER+NUMBER64, NUMBER+SYSTEMTIME, SYSTEMTIME+NUMBER64, NUMBER+COMMA, SYSTEMTIME+COMMA),
  then index != 0 with COMMA (12150), then index != 0 on levels 18..22 (12150, index untouched), then the CUSTOM rules,
  then the per-level mask (12154).
- The per-level masks: Content-Length allows REQ|NUMBER|NUMBER64. Date, Last-Modified, If-Modified-Since,
  Retry-After, If-Unmodified-Since and **Expect** allow SYSTEMTIME. STATUS_CODE allows only NUMBER. STATUS_TEXT,
  Refresh and Ms-Echo-Request allow nothing (not even REQ). FLAG_COALESCE is in no mask. COALESCE_WITH_COMMA is
  outside the mask bits, so it is accepted on every level.
  **Expires|SYSTEMTIME = 12154** because the Expires mask has no SYSTEMTIME bit. This explains the open item from
  laneg task 65. CUSTOM bypasses the masks: `CUSTOM "Expires"|SYSTEMTIME` converts.
  `hqi_args_modifier_mask_table` checks all 96 x 4 combinations: 375 rejected, 9 accepted.
- CUSTOM names: the name ends at NUL, `:`, CR or LF. An ASCII control character or whitespace before the end gives 87.
  Non-ASCII bytes are not validated. Matching is case-insensitive, and known names map to their level.
- String protocol (A): needs n+1 bytes. On success `*len = n` and the byte after the NUL is untouched. On 122
  `*len = n + 1`, and the buffer and index are untouched. A NULL buffer gets `*len` zeroed first, so (A, NULL, any
  length) gives 122 with the needed size, or 12150 with `*len = 0` when the header is absent.
- W: a NULL buffer with `*len != 0` gives 87. It needs 2(n+1) bytes, reports 2(n+1) on a 122 and 2n on success.
  **Quirk:** a W buffer of at least n+1 but less than 2(n+1) bytes gives 122 *after* A has already advanced the
  index (`hqi_buf_w_partial_buffer_advances_index`, `hqi_buf_w_custom_partial_buffer`).
- W + NUMBER64 on a known level is widened as text (8 raw bytes plus NUL become 9 WCHARs): an 8-byte buffer gives
  122/18, and a big buffer gives TRUE/16. CUSTOM|NUMBER64 under W is copied raw.
- Number conversion: "12abc" = 12, "abc" = 0, "-1" = 0, an empty value gives 12154, more than 32 bits gives 12153,
  more than 64 bits gives 534. A SYSTEMTIME value of 128 bytes or more gives 12004.
- Index: incremented only on success. A miss leaves it unchanged. COALESCE_WITH_COMMA joins with ", " and never
  touches the index.
- A successful query sets the last error to 0.
- REQUEST_HEADERS for every level matches what the server received (`hqi_lvl_request_side_matches_wire`), and
  `RAW_HEADERS_CRLF|REQUEST_HEADERS` is byte-identical to the request head on the wire.

## VM-observed only [W10]
- Before HttpSendRequest: STATUS_CODE = "0" (NUMBER 0), RAW_HEADERS_CRLF = "\r\n\r\n", and STATUS_TEXT/VERSION give
  12150. There is **no 12019**, although the decomp gates response queries on flag 0x200; the flag is evidently
  already set. REQUEST_METHOD and VERSION|REQ answer.
- The `lpszVersion` argument of `HttpOpenRequestA` is ignored: "HTTP/1.0" still goes out as HTTP/1.1.
- **HTTP/0.9 is not answered with 12151.** A response without a status line (or with more than 4 junk bytes before
  "HTTP", or truncated to "HTTP/" or "HTTP/1.1 2" before EOF, or a bare "HTTP/1.1" line) gets a synthesised
  HTTP/1.0 200. No headers are kept, and the whole stream is the body. The decomp path that returns 12151
  (`this[0x142c] & 2`) is not reached here.
- Status line: up to 4 junk bytes or blank lines before "HTTP" are skipped. Runs of SP/HT are accepted. A missing
  reason gives "" and the raw block rebuilds the line as "HTTP/1.1 200 " (trailing space). Trailing spaces in a
  reason are kept. The reason phrase is verbatim. Every code from 200 to 999 is reported as sent.
- Status token: the string form is the token as sent ("2x0", "abc", "-200", "0200"). The number stops at the first
  non-digit, and a value of 0 reads back as 0xFFFFFFFF. A token over 32 bits, or an empty token, makes
  HttpSendRequest fail with 12152.
- Every 1xx (100, 102, 103, 199, HTTP/1.0 100, 100 with headers) is consumed. Interim headers are discarded.
- An empty response gives 12152. RST gives 12031.
- Header lines: leading and trailing LWS is trimmed from values, inner whitespace is kept, and empty values are
  stored ("Name: " in the raw block). Whitespace before the colon is dropped from the name. Lines without a colon,
  lines with an empty name, and obs-fold continuation lines are **dropped** (not joined). A bare CR ends a line. A
  NUL inside a value is kept (length 3 for "a\0b"). LF-only and mixed line endings work. Name casing is preserved in
  RAW_HEADERS.
- Duplicates: the first Content-Length wins. A conflicting second one, or a list "3, 3", is not an error. Chunked
  trailers are not merged.
- Limits: 1000 distinct headers, 300 repeats, 128 KB values, and heads of 256 KB, 1 MB and 4 MB were all accepted.
  No size limit was hit.
- Header dates (laneg task 65 vectors plus new ones): names are case-insensitive. A date without a weekday, or in
  ISO 8601, gives 12154. A 127-byte value with trailing junk still parses. Values that depend on the clock (a bare
  number, an empty value, "Tue, 15 Nov") are only noted with `t_note`.
- `Ms-Echo-Reply`, `Ms-Echo-Request` and `X-P2P-PeerDist` in a response are stored and returned like ordinary
  headers.
- HEAD with Content-Length 1000 completes at once and reads 0 bytes. For 204/304 with Content-Length: 5, the read
  returns 0 bytes but only after the server closes; only the timing is noted.

## Knowledge-only [K] (checked, and confirmed by the VM run)
- Canonical reason phrases of the status table (the server sends them, so the CHECKs actually test that they are
  passed through verbatim).
- The Content-Encoding header stays visible with decoding off. Turning decoding on returns the decoded body.
  Whether the header is still visible then is only noted.

## Remaining notes (not CHECKed)
- RAW_HEADERS before send, STATUS_TEXT/RAW of a 0.9 response, the body of truncated 0.9 replies, and timing of
  HEAD/204/304: all recorded with `t_note`.
- The RST response error is CHECKed as 12031 from one observation. Re-check it with `vm_matrix.sh --twice` if it
  turns out to be flaky.

## Second pass (rsp_segments, rsp_lifecycle, hqi_generated, hqi_reqside, rsp_values)
Win10 boots `rh-20261110-051251-b1` (171 tests, 6 failures, triaged below) and `rh-20261110-063749-b1`
(173 tests, 42874 checks, 1 failure from a wrong probe, the REQ+COMMA pair, corrected), then `rh-20261110-082447-b1`: **PASS**, 173 tests, 42879 checks, 0 failures, 107 s.

### Decomp-grounded [D] (and confirmed on the VM)
- `HTTP_REQUEST_HANDLE_OBJECT::ReuseObject@0x3ade8` runs on a resend: it clears the response flags (+0x142c) and calls
  `CHttpHeaders::_Reset` on the response store (+0xc20). A second HttpSendRequest on the same handle keeps no header,
  index or status of the first response (`rsp_life_resend_*`).
- `CHttpHeaderParser::ParseHeaders@0x8a150` trims only SP and HT around a value. 0x01, 0x0B, 0x0C, 0x1F and 0x7F at
  either end are kept, and every C0 byte other than HT/LF/CR (and DEL) inside a value is kept verbatim. W widens them
  1:1 (`rsp_val_control_bytes_*`).
- Request side: FLAG_REQUEST_HEADERS reads the request store with the same `_FindHeader`/`_CopyValueToBuffer`
  protocol and the same per-level masks. `Max-Forwards|REQ|NUMBER` gives 12154, and `CUSTOM|REQ|NUMBER` converts
  (`hqi_req_numbers_and_dates`).
- `hqi_generated.c` checks a model built only from facts listed above: trimming, case-insensitive names, raw
  rebuild in arrival order with names as received, NUL layout, index walk and coalesce, and the A/W size protocol.
  It covers 250 pseudo-random responses (HTTP/1.1 CRLF and HTTP/1.0 LF-only), 35 pool names (26 known levels), random casing
  and padding, and duplicates.

### VM-observed [W10]
- Segmentation: splitting the head at every byte offset (CRLF and LF-only), at two offsets, in pieces of 1..4096
  bytes, inside an interim 100, at the end of the head with the body following, and in close-delimited, chunked and HEAD
  responses gives exactly the unsplit result.
- Lifecycle:
  - Headers are unchanged before, during and after the body read.
  - After an automatic 302 redirect only the final response is visible. REQUEST_HEADERS shows the final request line.
  - An InternetOpenUrl handle answers like an HttpOpenRequest handle, and its request raw block equals the wire.
  - HttpSendRequestEx: every query gives **12019** until HttpEndRequest is called. After it, the response and
    REQ Content-Length are queryable.
- After a send that fails with 12152 (an empty response, or a resend that the server closes), **every** query gives
  **12019** ERROR_INTERNET_INCORRECT_HANDLE_STATE, including REQUEST_METHOD and CUSTOM. After 12029 (connection refused) the
  handle answers as before a send: STATUS_CODE "0", RAW_HEADERS_CRLF "\r\n\r\n".
- Closing the connect handle (or the session) closes the request handle: queries give 6 (ERROR_INVALID_HANDLE).
- HTTPS (schannel loopback server) parses exactly like HTTP: trimming, dropped folds, duplicates, raw rebuild.
- Keep-alive: a request after HEAD+Content-Length:1000, 204 or 304 on the same connection is parsed correctly. One
  connection was used in each case (this is only noted).
- Request store before the send: `GET /r HTTP/1.1\r\n<added headers>\r\n`. Host and User-Agent are absent (12150)
  until they are sent. HttpAddRequestHeaders REPLACE removes the first occurrence and **appends** the new value at
  the end. REPLACE of an absent name adds it. ADD_IF_NEW on an existing name gives 12155. Headers passed to
  HttpSendRequest stay in the request and are sent once on a resend.
- W quirk on the request side too: a W buffer that holds the A copy but not the W one gives 122 with the index
  already advanced. `CUSTOM|REQ|COALESCE_WITH_COMMA` gives 87 for any buffer size (*len untouched): the
  REQ+COMMA pair is illegal [D].
- Reason phrases are stored verbatim: tabs, colons, UTF-8 bytes, and 4096 bytes. A second status line among the
  headers is dropped as a colon-less line. Headers named Status-Code/Version/Status do not affect the synthetic levels.
  Known-name look-alikes (`Server-Timing`, `Content-Types`, ...) are custom headers only.

### Corrections to the first pass
- `rsp_hdr_content_encoding_gzip_decoded` assumed that HTTP_DECODING alone decodes. Win10 decodes only when the
  request lists the coding [D _CheckDecompressionRequestHeaders, http_body_io EVIDENCE], so the test now sends
  `Accept-Encoding: gzip, deflate`.
- Test infrastructure: the loopback server accepts at most 64 connections (`SRV_MAXCONN`), so the every-offset
  loops restart it every 56 connections. The first boot's resets at offsets >= 65 came from that limit, not from wininet.
