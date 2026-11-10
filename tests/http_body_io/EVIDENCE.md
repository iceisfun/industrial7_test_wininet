# http_body_io: evidence for the expectations

Area prefix `bio_`. Files:

| File | Contents |
|---|---|
| `bio_read.c` | InternetReadFile contract, Content-Length size sweep (0 .. 1 MiB around 4096/8192/65536), integrity (CRC32/SHA-256), InternetOpenUrl handles, error-status bodies |
| `bio_framing.c` | chunked sizes and syntax, close-delimited, truncated Content-Length, no-body statuses, persistence, draining, re-send |
| `bio_chunk2.c` | chunk grammar table from the decomp (29 cases x 2 read sizes), many-chunk bodies, slow framing, QDA bounds |
| `bio_ex_qda.c` | InternetReadFileExA/W, InternetQueryDataAvailable, InternetSetFilePointer, async reads |
| `bio_decode.c` | HTTP_DECODING matrix, stored/Huffman gzip/zlib/raw, receive-timeout behaviour, resets, HTTPS bodies |
| `bio_decode2.c` | decoding rules from the decomp: Accept-Encoding gating, Content-Encoding gating, Content-Type exclusions, header rewriting, gzip/zlib/brotli stream variants, large expansions, option inheritance |
| `bio_more.c` | POST/PUT bodies, HTTP/1.0 request line, redirect bodies, split sweeps |
| `bio_misc2.c` | HttpSendRequestEx/HttpEndRequest, wide entry points, cache-backed bodies (NEED_FILE, seeking, FROM_CACHE), cancel by close, parallel readers, 206, interim responses, big heads, options, re-send |
| `bio_cl_variants.c` | Content-Length spellings and head variants (observed) |
| `bio_common.c`, `bio_wait.c`, `bio.h` | helpers; `bio_open` copies each script and inserts a non-blocking wait before every request read so `srv_stop` never waits out its 3 s grace on a pooled keep-alive socket |
| `bio_data.c/.h`, `gen_bio_data.py` | generated compressed bodies (python zlib/gzip/brotli from known plain text) |

Tags: **[D]** read in the Win10 22H2 decompilation (corpus explorer, `wininet.dll` 11.0.19041.2193);
**[VM]** observed on the local Windows 10 22H2 guest (10.0.19045.2965) through `tools/vm_run.sh`;
**[K]** WinINet knowledge, kept as a hard CHECK only after a VM pass agreed; **note** = recorded with `t_note`, never asserted.
Every hard CHECK in the area passed on the VM (see the boot list at the end).

## Decomp-grounded (and confirmed on the VM)

| Expectation | Source |
|---|---|
| InternetReadFile: `lpdwNumberOfBytesRead == NULL` -> 87; `*read` zeroed, then `lpBuffer == NULL` -> 87 (also with length 0) | [D InternalInternetReadFile] + [VM] |
| InternetReadFile / ReadFileEx / QDA on session or connect handle -> 12018, `*read` untouched | [D type switch] + [VM] |
| InternetReadFileExA: `dwStructSize != 0x38` -> 87; `dwBufferLength == 0` -> TRUE/0; `Next` not followed | [D InternetReadFileExA@0xa2e20] + [VM] |
| InternetReadFileExW: NULL buffers -> 87 before the handle is looked at; `lpcszHeader != NULL` -> 87 | [D InternetReadFileExW@0xa2d90] + [VM] |
| InternetQueryDataAvailable: NULL out -> 87; dwFlags/dwContext not validated | [D InternetQueryDataAvailable@0x76b20] + [VM] |
| InternetSetFilePointer: non-HReq -> 12018 / 0xFFFFFFFF; not cache-backed -> 12016 before the move method is checked | [D InternetSetFilePointer@0x138550, SetStreamPointer@0x16f818] + [VM] |
| Chunk grammar: byte classes hex/':'/CR/LF/other; size line must start with a hex digit; anything after the digits up to CR is an extension (`5zz`, `5 `, `5:x` = 5, `0x5` = 0); every line end exactly CR LF; data must be followed by CR LF; trailer lines need a ':'; >16 hex digits overflow | [D CHUNK_TRANSFER::GetToken@0x16ea0, ParseChunkInput@0x16af4] |
| Decoding happens only when the application's own Accept-Encoding lists the coding: exact `gzip, deflate` / `gzip, deflate, br`, else comma tokens trimmed and compared case-insensitively over their full length (`gzip;q=1.0` and `*` do not count, `x-gzip` token does not enable gzip) | [D HTTP_REQUEST_HANDLE_OBJECT::_CheckDecompressionRequestHeaders@0x664d4, StrCmpNICBounded@0xbdfa8] |
| Response side: exactly one Content-Encoding header with value gzip / x-gzip (needs the gzip token), deflate, br; Content-Types application/x-tar, x-gzip, x-compress, x-compressed (exact, case-insensitive) stay encoded; after decoding Content-Encoding is removed and `Accept-Encoding` is removed from Vary (Vary dropped when empty) | [D CheckDecompression@0xbdd3c, CHttpHeaders::RemoveTokenFromHeaderListByIndex@0x13408 (index 0x41 = Vary), table at 0x1f44b0] |
| Decompressor: gzip = zlib windowBits 31 only (zlib data labelled gzip fails); deflate = zlib 15 with a retry as raw deflate if nothing was produced (gzip data labelled deflate fails); br = brotli; a CRC32/Adler-32 mismatch ("incorrect data check") ends the stream cleanly; other inflate errors -> 12175 | [D DECOMPRESSOR::Init@0x1ed60, CreateDecompression@0x1ef0c, ZlibDecomp@0x1a50, Decompress@0x1b10, HttpReadData_Fsm@0x77430] |

## VM-observed

(Filled from the boots listed below.)

| Expectation | Boot |
|---|---|
| Read before send: TRUE, 0 bytes, nothing on the wire; QDA before send: TRUE/0 | 1 |
| GetLastError after successful reads is 0 | 1 |
| Truncated Content-Length body (server closes): TRUE with the bytes received, then TRUE/0 | 1 |
| RST mid-body (CL, chunked, close-delimited): read fails with 12031, and the bytes already buffered with the RST are not delivered (n = 0) | 1 |
| RST instead of a response: send fails 12031; graceful close instead of a response: 12152 | 1 |
| Malformed chunk size in the first buffered data (`zz`, `-5`, LF-only lines, bad second size in the same segment): HttpSendRequest itself fails with 12004 | 1 |
| HTTP_DECODING is copied from the session to the connect handle when the connect handle is created, and from the connect handle to the request when it is created; setting it later on the parent has no effect on existing children | 1 |
| A RECEIVE_TIMEOUT of 400-500 ms set on an existing session, on the request, or as DATA_RECEIVE_TIMEOUT does not cut a 2.5 s stall short (head or body): the call waits and succeeds | 1 |
| Cache-backed response: seekable while being read (back to 0, forward past what was downloaded); after the body was read to EOF, InternetSetFilePointer fails 12016 | 1 |
| INTERNET_OPTION_DATAFILE_NAME with NO_CACHE_WRITE: 12028; with NEED_FILE: file content == body | 1 |
| FROM_CACHE second handle: same body, no request on the wire, REQUEST_FLAGS has FROM_CACHE (0x1); fresh response flags 0x40 | 1 |
| InternetReadFile between HttpSendRequestEx and HttpEndRequest: 12019 | 1 |
| InternetCloseHandle on a request blocked in InternetReadFile: the read returns FALSE 12017 at once | 1 |
| Unread extra bytes after a CL body: the connection is not reused for the next request | 1 |
| HttpOpenRequest's lpszVersion "HTTP/1.0" and INTERNET_OPTION_HTTP_VERSION 1.0 do not change the request line (still HTTP/1.1) | 1 |

## Knowledge-only / notes

Recorded with `t_note` because they describe values or environment-dependent behaviour: first/largest QDA values (8192 for
CL bodies, 8173 for chunked), number of reads, connection counts after an abandoned body (drained bodies of 100 bytes
and 500000 bytes both moved the next request to a new connection), Content-Length after decoding, outcomes of
contradictory Content-Length headers (`bio_clv_*`), corrupt gzip streams and odd stream ends (`bio_d2_gzip_two_members`,
`..._trailing_garbage`, `..._no_trailer`, `..._bad_isize`), receive-timeout probes with the timeout set before
InternetConnect, seek past the end.

## Boots

| Boot | Run dir (`~/w10lab/runs/`) | Result |
|---|---|---|
| 1 | `wininet-bio-20261110-050214-b1` | 329/496 tests before the 780 s cap (srv_stop waited 3 s per test); failures triaged above |
