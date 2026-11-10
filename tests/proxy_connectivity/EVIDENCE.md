# proxy_connectivity: evidence

Prefix `pc_`. Five files: `pc_options.c` (InternetOpen access types, INTERNET_OPTION_PROXY / PROXY_USERNAME / PROXY_PASSWORD,
PER_CONNECTION_OPTION read-only, connected-state options), `pc_connectivity.c` (connected state, InternetCheckConnection,
InternetGoOnline, InternetAttemptConnect, DoConnectoidsExist, DetectAutoProxyUrl, InternetInitializeAutoProxyDll,
InternetGetProxyForUrl, IsHostInProxyBypassList), `pc_proxy_wire.c` (forward proxy, CONNECT tunnel, bypass lists),
`pc_failures.c` (refused, DNS, timeouts, resets), `pc_util.c` (helpers: closed-port finder, CONNECT relay, bounded worker).

No network: proxies, origins and tunnel endpoints are loopback servers started by the test (common/srv + a raw CONNECT
relay in `pc_util.c`). Origin hosts are `*.invalid`: proxied requests never resolve them; a request that bypasses the proxy
fails at once with 12007 (the lab guest has no DNS), which makes "proxied vs direct" observable. Nothing changes
per-user or process-wide proxy state: INTERNET_OPTION_PROXY is set only on session handles, PER_CONNECTION_OPTION is
only queried (the set path is exercised only with invalid arguments that fail before the registry).

Oracle: Windows 10 22H2 VM (`tools/vm_run.sh proxy_connectivity`), wininet 11.0.19041.2193. Tags below:
**D** = read in the corpus decomp first and confirmed on the VM; **V** = observed on the VM (decomp silent or not read);
**K** = WinINet knowledge, confirmed on the VM; **N** = t_note only (environment- or timing-dependent).

## InternetOpen / INTERNET_OPTION_PROXY
| fact | tag |
|---|---|
| access 0, 1, 3 (non-empty proxy), 4 accepted; 2, 5..9, 0x10, 99, 0x80000000, ~0 -> NULL / 87 (A and W) | D InternalInternetOpen@0xe0650 |
| PROXY with NULL or "" proxy -> 87 | D |
| bypass "192.0.2.0/24" (CIDR) -> InternetOpen fails 87 | V |
| DIRECT / PRECONFIG session query PROXY -> access 1, NULL strings, len 24; short buffer -> 122 need 24; NULL len -> 87 | D LegacyGetSessionProxySettings@0x15fb2c |
| named session: proxy and bypass lowercased (CharLowerA), ';' and ',' -> ' ' | D LegacyGetProxySettings@0x166840 |
| **quirk**: lpszProxyBypass points at a second copy of the proxy followed by " <bypass>" (or the bare proxy copy when there is no bypass); size = 24 + 2*(strlen(proxy)+1) [+ strlen(bypass)+1]; lpszProxy = buffer+24 | D + V (62 / 48 / 34 / 112) |
| InternetQueryOptionW(PROXY) returns the A struct with ANSI strings | D InternetQueryOptionW@0xc5d50 (falls through to A) |
| PROXY on connect/request handles: query and set -> 12018 | D |
| set PROXY: length != 24 -> 12010, len 0 / NULL buffer -> 87, access 2/4/5/... -> 87, PROXY with NULL/"" -> 87 | D InternetSetOptionA case 0x26 |
| set PROXY on a session is session-scoped (other sessions and the NULL handle unchanged) and re-routes later requests | V |
| PROXY_USERNAME/PASSWORD: session and NULL handle -> 12018 (query, set, A and W); connect/request handles: fresh = "" len 0, A size = strlen+1, W size = bytes incl NUL, W set visible to A query | D cases 0x2b/0x2c + V |
| PER_CONNECTION_OPTION query: NULL buffer -> 87, len < 0x20 -> 12010, unknown option id -> 87 with dwOptionError = index, 0 options ok | D QueryPerConnOptions@0x13b2c0 |
| PER_CONNECTION_OPTION on a PROXY session reports the global settings (FLAGS 0x9 in the lab), not the session proxy | D + V |
| CONNECTED_STATE / AUTODIAL_MODE = 1, IDLE_STATE / OFFLINE_SEMANTICS = 0 (NULL handle and session) | D case 0x32..0x34, 0x52 |
| set CONNECTED_STATE with a length != 8 -> 12010 | D |
| set CONNECTED_STATE with 8 bytes **succeeds** from a normal process (decomp suggested 12004) - removed from this area because it toggles offline mode; belongs in a dx_ area | V (run 1) |
| OFFLINE_MODE query: NULL handle -> 12018, session -> 120 | D + V |
| MAX_CONNS_PER_PROXY (103) = 4 | V |

## Connectivity entry points
| fact | tag |
|---|---|
| InternetAttemptConnect(0) = 0, nonzero -> 87 returned (GetLastError untouched) | D @0x1378d0 |
| InternetGetConnectedState: flags zeroed first; reserved != 0 -> FALSE/87; lab: TRUE, flags 0x12 (LAN \| RAS_INSTALLED), name "LAN Connection" | D @0xd8340 + N (value) |
| ExA = ExW converted with a 0x101 WCHAR buffer; short A buffer gets its last byte forced to NUL | D @0x286e0 |
| InternetGoOnline/A/W: flags & ~3 -> FALSE/87, else TRUE/0; URL and hwnd ignored | D @0x13c830/0x13c8f0 |
| DoConnectoidsExist is ordinal 101 only (no name); lab: 0 | D + N |
| InternetGetProxyInfo / InternetDeInitializeAutoProxyDll are not exported | V (export table) |
| InternetCheckConnection: reserved != 0 -> 87; FORCE to listening port -> TRUE after a bare TCP connect (no request); closed port -> 12029; .invalid -> 12007 (~12 s in the lab); "not a url"/"http//x" -> 12006, "mailto:" -> 87 | D @0x137a50 + V |
| InternetCheckConnection without FORCE ignores the URL: fresh process -> 2250 ERROR_NOT_CONNECTED; FORCE + NULL url in a fresh process -> 12016; after any connection in the process -> TRUE | D (FindNearestServer) + V (child process) |
| DetectAutoProxyUrl: len 0 -> 122, NULL buffer -> 87, buffer cleared first; lab: 12180 for DHCP/DNS_A | D @0x165bb0 + V |
| 12180 has no message text in wininet (FormatMessage -> 317) | V |
| InternetInitializeAutoProxyDll: bits above 0xF or (0x4\|0x8 with 0x2) -> 87; 0,1,2,4,5,8,0xC -> TRUE/0 | D @0x5bf80 + V |
| InternetGetProxyForUrl returns a DWORD: NULL/"" url, NULL list, non-session handle -> 87 (list zeroed first); closed handle -> 6; uses the GLOBAL configuration even for a PROXY session (lab: 1 entry, fProxy FALSE) | D @0x16578c + V |
| IsHostInProxyBypassList: scheme not 0/1/3/4 -> FALSE/12006; NULL or "" host -> 87; lab (no proxy) -> FALSE for every host | D @0x5eea0 + V |

## Forward proxy wire (CERN proxy on loopback)
| fact | tag |
|---|---|
| request line is absolute-form `GET http://host[:port]/path?q HTTP/1.1`; Host = host[:port], explicit :80 dropped | K + V |
| proxied InternetOpenUrl GET carries exactly User-Agent, Host, Pragma: no-cache (no Proxy-Connection, no Connection, no Cache-Control) | V |
| POST/HEAD through the proxy keep their verb and body | V |
| one keep-alive connection to the proxy serves several origins | V |
| 407 + Basic with PROXY_USERNAME/PASSWORD set: automatic re-send with `Proxy-Authorization: Basic b64(u:p)`; no pre-emptive Proxy-Authorization; without creds the 407 is returned (status 407, body readable); creds set after the 407 + re-send work; HTTP_QUERY_PROXY_AUTHENTICATE readable | K + V |
| origin 401 through the proxy uses Authorization (InternetConnect creds), never Proxy-Authorization | K + V |
| successful Basic origin credentials are cached process-wide and sent pre-emptively by a new session to the same host | V |
| proxy list syntax: `host:port`, `http=`, `HTTP=`, `http://host:port`, `http=http://`, `;` or space separated, surrounding blanks and a trailing `;` accepted; `https=`/`ftp=`/`socks=`-only lists leave http direct | V |
| no failover: `dead;alive` fails 12029 without trying the second proxy | V |
| bypass matching: `<local>` = names without a dot; `*` wildcards (prefix and suffix), case-insensitive; separators `;`, space and `,`; no `?` wildcard; `*.x` does not match bare `x`; `scheme://host` entries are scheme-specific; `host:port` entries are port-specific; IP literal and `192.0.2.*` patterns work | V |
| loopback (127.0.0.1, localhost, [::1]) is bypassed implicitly; `<-loopback>` (case-insensitive) sends it to the proxy, also together with `<local>` | D IsLoopbackMacro + V |
| ftp:// URL through a CERN proxy = HTTP GET `ftp://host/path` with `Host: host:21`, returned as an HTTP request handle (type 13) | V |
| CONNECT: `CONNECT host:port HTTP/1.0` with exactly User-Agent, Host: host:port, Content-Length: 0, Proxy-Connection: Keep-Alive, Pragma: no-cache (in that order); inside the tunnel the request is origin-form with the origin Host and no proxy headers | V |
| CONNECT 407 + creds -> second CONNECT (new connection) with Proxy-Authorization, then 200; 407 without creds / 403 / 502 are returned as the request's status | V |
| https through the proxy with InternetOpenUrl (no ignore flags) -> CONNECT then 12045 | V |
| bypassed https goes direct (12007, no CONNECT) | V |

## Failures
| fact | tag |
|---|---|
| refused loopback port -> 12029 after ~2 s (direct, HttpSendRequest, https, FTP InternetConnect, via proxy) | K + V (F3) |
| CONNECT_TIMEOUT 300 ms against a refused port -> 12002 (after ~2 s) | V |
| `.invalid` -> 12007 at once (http, https, port 8080, HttpSendRequest twice, FTP connect); a dotless name costs ~2.3 s | V + N |
| unresolvable proxy name -> 12007 (~12 s) | V + N |
| no response then close -> 12152; RST before/mid headers -> 12031; partial status line, partial headers -> 200 (HTTP/0.9-style fallback / headers taken as complete); garbage -> 200 with the bytes as body; truncated body / close-delimited -> 200; identical through a proxy | V |
| RST mid body: InternetReadFile fails 12031 and the already-received bytes are not delivered | V |
| RECEIVE_TIMEOUT 800 ms against a 3 s stall: NOT honoured in run 1 (200 after ~3 s); kept as t_note probes (session and request handle) | N |
| stale keep-alive connection closed by the server is retried on a new connection | V |

# Pass 2 (files `pc_dial.c`, `pc_options2.c`, `pc_proxy_wire2.c`, `pc_failures2.c`)

Win10 boots: 3 (baseline of pass 1, 122/123; the failing creds-cache test depended on the script position, fixed with
per-connection scripts), 4 (pass-2 probes; the area hit the 300 s limit, so `VM_TIMEOUT` is now 720), 5 (246 tests, 13
failing), 6 (239/239 PASS, 2831 checks, 402 s), 7 (confirmation after promoting boot-6 notes).

**Harness finding (boot 5).** `EXPECT_EQ`/`EXPECT_NE` in `common/t.h` evaluate their first argument twice (once in the
comparison and once for the "got" value). Every `EXPECT_EQ(pc_get(...), 200)` therefore sent its request twice, and Wine
showed the same doubling. `pc.h` now redefines single-evaluation versions for this area. Pass-1 wire facts that counted
requests were re-observed in boot 6. Other areas that pass side-effecting calls to `EXPECT_EQ` have the same problem.
Decomp references are wininet 10.0.19041 RVAs from the corpus API.

## Option read-back and set details (`pc_options2.c`)
| fact | tag |
|---|---|
| PROXY read-back: CharLowerA, `;` and `,` -> ` `; nothing else changes (leading/trailing blanks, tabs, `;;` -> two blanks, `http= x` kept verbatim) | D LegacyGetProxySettings + V |
| `http =x:1` (blank before `=`) is rejected by InternetOpen(PROXY) with 87 | V |
| bypass read-back follows the same rules (`<LOCAL>` -> `<local>`); empty bypass `""` = no bypass (len 24+2*(n+1)) | V |
| W open: strings converted to ANSI, A and W queries return identical buffers | V |
| short buffer, named session: the first min(len,24) bytes are zeroed, nothing past them; DIRECT session: the whole short buffer zeroed; need stays exact | D (memset in LegacyGetProxySettings) + V |
| required size = 24 + 2*(strlen(proxy)+1) for proxies of 3..259 chars and a 4011-char list (need 8048) | V |
| query/set PROXY on a closed session -> 6 ERROR_INVALID_HANDLE | V |
| PROXY query on an (offline) FTP connect handle -> 12018 | D |
| set PROXY with access PRECONFIG (0) on a session succeeds and reads back the global setting (lab: DIRECT, len 24) | D case 0x26 + V |
| set PROXY DIRECT ignores the strings; a new PROXY set replaces the bypass list; 50 alternating sets read back correctly | V |
| PROXY_USERNAME/PASSWORD: set length 0 or NULL buffer -> 87; any other length stores the whole NUL-terminated string; "" accepted (len 0); values up to 1000 chars round-trip; request handle copies the connect handle's values at HttpOpenRequest, later request sets do not touch the connect handle; W set of non-ASCII readable via A (CP_ACP) and W | V |
| PER_CONNECTION_OPTION: FLAGS_UI = FLAGS; each option 1..10 queryable alone; A and W agree; list.dwSize not validated (0, 4, 0x1f, 0x40, ~0 all accepted, len stays 0x20); unknown connectoid name accepted; dwOptionError = index of the first bad option, earlier entries filled | D QueryPerConnOptions + V |
| lab values: FLAGS 0x9 (DIRECT \| AUTO_DETECT), every string NULL, AUTODISCOVERY_FLAGS 0, LAST_DETECT_TIME 0 | N |
| set PER_CONNECTION_OPTION on the NULL handle: NULL buffer or len 0 -> 87; len 1..0x1f -> 12010 (never reaches the registry) | V |
| REFRESH (37) on NULL, PRECONFIG and PROXY sessions -> TRUE (the PROXY session keeps its proxy); on a connect handle -> 12018 | D case 0x25 + V |
| SETTINGS_CHANGED (39) and PROXY_SETTINGS_CHANGED (95) -> TRUE; querying 37/39/95 -> 87 | D + V |
| SETTINGS_CHANGED purges pooled keep-alive connections: the next request of an existing session opens a new one | D case 0x27 (PurgeKeepAlivesAndDuos) + V |
| query table (NULL / session): 50=1/1, 51=0/0, 52=0/0, 64=0/0, 70 -> 50/50, 82=1/1, 83 ok len 0 (first byte cleared) both, 85 -> 12018/87, 103 = 4 / 12016, 54..57 -> 12018/50 | D cases 0x32..0x39, 0x46, 0x53 + V |

## Dial / RAS stubs, connectivity (`pc_dial.c`)
| fact | tag |
|---|---|
| InternetAutodial: flags & ~0xF -> FALSE/87; else TRUE/0 when RAS is present (Win10: yes, INTERNET_RAS_INSTALLED); never dials, HWND only traced | D @0x13c520 + V |
| InternetAutodialHangup(0) TRUE/0, nonzero -> FALSE/87 | D @0x13c5e0 + V |
| InternetDial(A/W) return a DWORD: *lpdwConnection zeroed first; reserved != 0 or NULL lpdwConnection -> 87; flags unchecked; else 0; InternetDial == InternetDialA | D @0x13c690/0x13c760 + V |
| InternetHangUp returns 0 (reserved 0) or 87, never touches GetLastError | D @0x13c9b0 + V |
| InternetSetDialState(A/W) always FALSE/120 | D @0x13ca50/0x13cab0 + V |
| InternetAutodialCallback is a no-op | D @0x133af0 + V |
| GetProxyDllInfo returns pointers into wininet's image (aProxyFileList, CLSID_PSFactoryBuffer), stable across calls | D @0x132630 + V |
| InternetGetConnectedStateExW: name = LoadStringW(cch) -> truncated to cch-1 chars ("LAN Connection" in the lab); ExA: short buffer gets b[len-1]=0, returns TRUE with GetLastError 122 from WideCharToMultiByte; reserved != 0 -> 87 with flags and name zeroed | D @0xd8340/0x286e0 + V |
| InternetCheckConnection FORCE: http/https URL forms (with path, query, fragment, userinfo, localhost) = bare TCP connect, no request; ftp:// waits for an FTP banner (12111 after ~5 s against an HTTP peer); gopher -> 87; closed port -> 12029 for every scheme; only bit 0 of dwFlags is FORCE | D @0x137a50 + V |
| InternetCheckConnection URL table: "", "http://", "not a url", "http//x" -> 12006; "http:///path", port 99999 -> 12005; "mailto:", "javascript:" -> 87; "file:///", "about:blank" -> TRUE; port 0 -> 12029; host over 256 chars -> TRUE without connecting | D + V |
| InternetGetProxyForUrl(NULL, url): http, https, ftp, ws, wss, gopher, mailto, [::1], 127.0.0.1 -> 0 with 1 entry (lab: fProxy/fBypass FALSE, port 0); file:///, "http://" -> 12005; "not a url", bare host -> 12006; a second InternetFreeProxyInfoList is a no-op | V |
| DetectAutoProxyUrl: flags other than DHCP/DNS_A bits (0, 4, 8, 0x80000000) -> 87; buffer[0] cleared, nothing written past it; lab -> 12180 | D @0x165bb0 + V |
| IsHostInProxyBypassList (lab, no proxy): FALSE for every host and length, GetLastError 0; "<local>" -> FALSE/12005 | V |

## Forward proxy wire, part 2 (`pc_proxy_wire2.c`)
| fact | tag |
|---|---|
| request line lower-cases the host but `Host:` keeps the caller's casing; `a b` -> `a%20b`, `/dir/../x` -> `/x`, userinfo dropped (no Authorization), explicit :80 dropped | V |
| absolute-URI request line keeps the **fragment** (`GET http://h/a#frag HTTP/1.1`); `%20`, `%26` kept; IPv6 literal `[2001:db8::1]:8080` and IP literals as given; ftp URLs with userinfo keep it in the line (`GET ftp://u:pw@h/f`) | V |
| HttpOpenRequest(version "HTTP/1.0") through a proxy still sends HTTP/1.1 | V |
| INTERNET_OPTION_URL on a proxied request = origin URL; request headers first line is origin-form | V |
| User-Agent is the InternetOpen agent verbatim; an empty agent sends no User-Agent | V |
| redirects through the proxy: absolute and relative Location re-requested through the proxy in absolute form; to a loopback origin -> direct (implicit bypass); to a bypassed name -> direct (12007); NO_AUTO_REDIRECT returns the 302 | V |
| 407: proxy credentials are cached per proxy and sent pre-emptively on later requests (other origins too); always-407 -> exactly one retry, 407 returned; 407 + Connection: close -> retry on a new connection; connect-handle PROXY_USERNAME/PASSWORD used; POST body re-sent | V |
| `http=` only list: https goes direct (12007); `http=A;https=B`: http to A, CONNECT to B; `HTTPS=` upper-case accepted; `ftp=` entry used for ftp:// as a CERN GET | V |
| two https requests with ignore-certificate flags: a new CONNECT (and connection) each, no tunnel reuse; `Proxy-Connection: close` from a proxy ends the keep-alive | V |
| CONNECT to IP literals: `CONNECT 192.0.2.10:443`, `CONNECT [2001:db8::5]:443`, Host the same; 200 reply variants (HTTP/1.0, extra headers, Content-Length: 0) all accepted; custom and Authorization headers stay inside the tunnel | V |
| bypass list: blanks around entries, empty entries, case ignored; `;` or ` ` alone bypass nothing; trailing-dot entry does not match; `*.*`, `pc-ws.*`, `*ws*`, `**` match; `http://*.invalid` matches http, `ftp://*.invalid` does not; `*.invalid:80` matches an implicit :80; a 7 KB list works; `<local>` = dotless names (any case, any port) | V |
| session HTTP_DECODING did not decode a gzip InternetOpenUrl body through the proxy (raw bytes returned) | V (note) |

## Failures, part 2 (`pc_failures2.c`)
| fact | tag |
|---|---|
| CONNECT failures: close -> 12152, RST -> 12031, garbage / partial status / 200-then-close -> 12029, 200-then-RST -> 12031, 200-then-plaintext -> 12157, 301/100-then-close -> 12152; 407 without challenge and HTTP/1.0 403 are returned as the status | V |
| server misbehaviour (identical direct and via proxy): close at accept / 100-then-close -> 12152, RST at accept -> 12031; response sent before the request is read -> 200 with it; status line only -> 200 empty; one byte "H" -> 200 body "H" (0.9); LF-only head, no reason phrase, `HTTP/2 200`, lowercase `http/1.1` -> 200; 999 -> 999; truncated chunk -> 200 with the partial bytes; bad chunk size -> 12004; negative or garbage Content-Length -> 200 empty body | V |
| after a refused HttpSendRequest the handle still answers status queries and InternetReadFile (0 bytes), and the request headers stay queryable; a second send fails 12029 again; the session keeps working | V |
| `.invalid` names: the first lookup in the process took ~12 s in the lab, the following ones 0 ms (all 12007) | V + N |
| URL ports: 0 and empty -> tried (12029); 65536, 99999, -1, abc -> 12005 | V |
| timeouts on a PROXY session: connect 60000, send/receive/data 30000, retries 5; CONNECT_TIMEOUT 0 reads back 0xFFFFFFFF; values copied to children at creation | V |
| message texts (en-US): 12002, 12007, 12029, 12030, 12031, 12152, 12005, 12006, 12018 "The supplied handle is the wrong type for the requested operation", 12010 "The length is incorrect for the option type", 12009 "The option is invalid" | V |
