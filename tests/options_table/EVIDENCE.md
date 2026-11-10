# options_table: where the expectations come from

Area: `InternetQueryOptionA/W` and `InternetSetOptionA/W` over the whole `INTERNET_OPTION_*` number space (0..200,
plus 201, 202, 255, 256, 1000, 99999 and 0xFFFFFFFF), for every handle type the tests can build without the internet.
Oracle: genuine Windows 10 22H2 (10.0.19045.2965, wininet.dll 11.0.19041.2193) on the local QEMU VM.
Wine was used only to check that the plumbing works (child processes, table replay). Its wininet results were not
used as evidence.

Evidence tags used below:
* **[VM]**: observed on the Win10 VM and frozen. The large tables were frozen from a probe that ran twice per boot
  (two passes, or two processes), and anything that differed between the runs is masked.
* **[D]**: grounded in the decompilation from the corpus explorer (`InternetQueryOptionA@0x59730`,
  `InternetQueryOptionW@0xc5d50`, `InternetSetOptionA@0x551b0`, `InternetSetOptionW@0x53e10`, `IsPerProcessOption@0x53ce8`,
  `IncrementCurrentSettingsVersion@0x1a8d8c`).
* **[K]**: general WinINet knowledge. Nothing tagged only [K] is a hard CHECK.

## Handle kinds (ot.h)
N = NULL handle, S = `InternetOpenA` DIRECT session, C = HTTP connect, R = unsent request, X = request sent and read
to the end, T = HTTPS request (loopback schannel server, `IGNORE_UNKNOWN_CA` after the documented first 12045),
F = FTP connect (loopback FTP server, passive), L = `InternetOpenUrl` on a `file://` URL.
Every server is in-process on 127.0.0.1.

## Generated tables (VM-frozen)
| file | generator | probe | what it pins |
|---|---|---|---|
| `ot_qtab.c` (3330 rows) | `gen/gen_qtab.py` | `gen/probe.c` tests `pq_NNN`, boot optr2: `gen/probe_query_rt_win10.txt.gz` and a second process `gen/probe_query_win10_pass2.txt.gz` | per (option, kind N S C R X T F L, A/W) four query probes: NULL buffer with len 0, 4096 buffer, exact length, length 1. Pins r, GetLastError and *len, plus the value bytes when the value is at most 16 bytes |
| `ot_stab.c` | `gen/gen_stab.py` | `gen/probe.c` CHILD setp, boot optprobe-20261109 (`gen/probe_set_win10.txt.gz`) | per option, 110 set calls on S C R X N (NULL/0, NULL/4, &0/0, lengths 1/3/5/8, round trip of the queried value, DWORD 0/1/0x7fffffff, A and W): TRUE or the error |
| `ot_rtab.c` | `gen/gen_rtab.py` | `gen/probe.c` CHILD rtp, two passes, boot optr2 | per option, for N S C R: initial query, then set DWORD 0,1,2,3,4,0x10,0x7fffffff,0x80000000 (length 4) and query back. Shows clamping, normalisation to 0/1, masks, ignored sets, set-only options |
| `ot_inherit_tab.h` | copied from the `INH` lines | `ot_inherit.c` itself, boot optr2 | for 27 options: value set on a session vs. connect/request created before and after |

Masked as volatile (only r/e/len compared, never the bytes): 1 CALLBACK, 21 PARENT_HANDLE (handle values),
24 EXTENDED_ERROR, 27, 32/35 certificate (dates, pointers), 33 DATAFILE_NAME (user profile path), 34 URL on R/X/T/L
(ephemeral port, scratch path), 66, 67, 69, 105 (pointers/sockets), 109, 117, 129, 186 (request times, found by
comparing the two runs), and 192 (caller module: image base, ASLR changes it per boot).

The set matrix never runs 39 SETTINGS_CHANGED and 95 PROXY_SETTINGS_CHANGED. Both bump the settings version in the
shared URL-cache header through IncrementCurrentSettingsVersion [D], which is a cross-process side effect.
It also never runs 42 END_BROWSER_SESSION and 154 (EndBrowserSession [D]). For 75 PER_CONNECTION_OPTION it skips the
round-trip set, because SetPerConnOptions writes the per-user registry. The round-trip matrix also skips 37 REFRESH.
Every other set runs in its own child process, so per-process globals cannot leak between options.

## Main findings (all [VM] unless tagged)
* Query entry rules [D][VM]: a NULL `lpdwBufferLength` gives 87, before anything else, including on stale handles.
  A NULL buffer sets *len to 0 first and then follows the 122 rule. On the NULL handle only per-process options
  succeed: 2-8, 24, 38, 40, 50-52, 59, 63, 64, 73-75, 82, 83, 103. Other numbers inside 1..0xC0 give 12018 with
  *len = 0, and numbers outside that range give 12009. On a real handle an unknown number gives **87**
  (the `default:` arm), not 12009. This covers 0, 201+ and 0xFFFFFFFF, and also the 118 numbers inside the range
  that have no query case.
* The W wrapper of the string options (28, 29, 33, 34, 41, 43, 44, 53) rejects a NULL handle without calling A,
  so `*len` stays as the caller passed it. A forces it to 0.
* Set-only options give 87 on query (the inheritance table shows 11, 62, 81, 114, 121, 125, 133, 138, 141, 148, 158,
  162, 172, 174, 177-180). 15, 16, 26, 30 and 78 give 120 on query, and 54-57 and 70 give 50 [D][VM].
* Set entry rules [D][VM]: a NULL buffer or a zero length gives 87 before the handle is looked at, except for the
  buffer-less options. A NULL-handle set of USERNAME/PASSWORD (28/29) succeeds (process-wide credentials, set
  matrix). For that reason `ot_rule_set_null_handle` leaves them out.
* Fixed-size values: 122 with the size on a NULL or short buffer. Strings (A): success gives *len = strlen, and
  122 gives strlen+1. Strings (W): success gives *len in characters, and 122 gives bytes including the NUL [D][VM]
  (`ot_strings.c`, qtab rows of 28/29/41/43/44/53).
* Timeouts are per handle and copied from the parent when the handle is created. CONNECT_TIMEOUT 0 is accepted
  and ignored, BACKOFF always reads 0, and values are not range-checked [D][VM] (`ot_timeouts.c`, inherit rows 2/6).
* MAX_CONNS_PER_SERVER / PER_1_0_SERVER: the global defaults on the image are 2 and 4 (noted, registry-configurable).
  Sets are clamped to 2..128, and 0 gives 160 [D][VM]. On a connect handle, PER_SERVER reads or sets the limit of
  the connect's CServerInfo. When the connect has none, the result is 12016 [D]. Whether an unused connect already
  has one differed between boot optr2 (separate processes per group) and boot optr3 (one process), so the
  hand-written tests accept either outcome and only note it. The round-trip table pins the fresh-process sequence.
  PER_1_0_SERVER on any real handle gives 12016 [D][VM]. S and R give 12016.
* PROXY (38): the bypass list that comes back starts with the proxy server itself ("127.0.0.1:9 <local>"). The
  W query forwards to A unchanged: same size and **ANSI** strings behind the LPCWSTR fields. A short set length
  gives 12010. C and R give 12018.
* USER_AGENT: an empty string (A or W) gives 12010. A copies up to the first NUL, whatever length it is given.
* SECURITY_FLAGS on a plain-HTTP request reads 0 and accepts the ignore bits without keeping them. The TLS request
  reads 0x20000101 (with IGNORE_UNKNOWN_CA set before the send).
* SECURITY_CERTIFICATE_STRUCT (32): a NULL buffer gives **TRUE** with *len 64. A short buffer gives **12004**.
  Non-TLS requests give 12016.
* SECURITY_CERTIFICATE (35): the size probe gives 122 with *len **1** (the text is formatted into the caller's
  buffer). A large buffer succeeds ("Subject:\r\nlocalhost\r\nIssuer:\r\n...", 228 chars here). A buffer of exactly
  strlen gives 122 with *len 1 again.
* SERVER_CERT_CHAIN_CONTEXT on a non-TLS request gives 12019. DIAGNOSTIC_SOCKET_INFO on a request read to the end
  (and on an unsent one) gives TRUE with INVALID_SOCKET, ports 0 and flags 0.
* EXTENDED_ERROR after a refused connect reads 997 on the VM. That is noted only, because it depends on the
  thread's history.
* REQUEST_FLAGS: an unsent request reads 8 (INTERNET_REQFLAG_NO_HEADERS). A sent `T_INET_FRESH` request reads
  0x40 (CACHE_WRITE_DISABLED), and a cache hit reads 1 (FROM_CACHE).
* Inheritance: HTTP_DECODING (65), CODEPAGE (68, default 0xFFFFFFFF), 100/101, IDN (102, default 3), 155 and 157
  set on the session are copied into connects and requests created **afterwards**. Existing children keep their
  values.

## Hand-written tests and their evidence
| file | tests | evidence |
|---|---|---|
| ot_rules.c | entry rules, NULL/stale/bogus handles, handle types, read-only and not-implemented options | [D] + [VM] (boots optr2/optr3/optr4) |
| ot_values.c | version, HTTP_VERSION global, fixed answers, context value, parent, buffer sizes, code pages, decoding, request flags, security flags, buffer-less actions, max conns | [D] + [VM] |
| ot_timeouts.c | timeouts, retries, connection limits | [D] + [VM] |
| ot_strings.c | USER_AGENT, URL, USERNAME/PASSWORD/PROXY_*, SECONDARY_CACHE_KEY: exact A/W size contracts | [D] + [VM] |
| ot_struct.c | PROXY structure on A/W, per-session proxy set, USER_AGENT edge cases | [VM] (structure layout [D]) |
| ot_tls.c | TLS options on the loopback HTTPS request | [VM]. Cipher, key size and protocol strings are noted only |
| ot_misc.c | callback, socket info, extended error, request-state gates, per-connection option, DATAFILE_NAME, REQUEST_FLAGS from cache, KEEP_CONNECTION | [D] + [VM]. Cache paths are noted only |
| ot_query_matrix.c / ot_set_matrix.c / ot_rt_matrix.c / ot_inherit.c | table drivers (each range or option in a child process) | [VM] tables above |

Knowledge-only ([K]) items appear only as `t_note`: registry-dependent defaults (MAX_CONNS, MAX_CONNS_PER_PROXY = 4
on the image), cipher/protocol names, the DATAFILE_NAME path, and EXTENDED_ERROR values.

## Re-freezing
Build the probe (`x86_64-w64-mingw32-gcc -Icommon tests/options_table/gen/probe.c common/*.c -static ...`), run it on the
VM (it takes about 8 s), then:
`gen_qtab.py run1.txt run2.txt > ot_qtab.c`, `gen_rtab.py run.txt > ot_rtab.c`, and copy the `INH` lines of an
`ot_inh` run into `ot_inherit_tab.h`.

## VM runs
| boot | content | result |
|---|---|---|
| optprobe-20261109-170901 | set probe (frozen into ot_stab.c) | data |
| optr2-20261110-050542 | probe (query + round trip, 2 passes), every hand-written group in its own process, inheritance observation | data. Hand-written failures were triaged: 9 expectations corrected from the observed values, 2 relaxed to t_note |
| optr3-20261110-061011 | full area, one process | 125/128 pass. Every generated matrix passes. 3 fixes: REQUEST_FLAGS constant name, MAX_CONNS on unused connects (state-dependent, relaxed) |
| optr4-20261110-074816 | full area after the fixes, one process | **PASS** 128/128 tests, 4752 checks in the parent plus every matrix child (0 mismatches) |
