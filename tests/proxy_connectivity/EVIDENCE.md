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
per-connection scripts), 4 (pass-2 probes; area hit the 300 s limit, so `VM_TIMEOUT` is now 720), 5+ (see below).
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
| SETTINGS_CHANGED did not make the next request of an existing session open a new connection | V (note) |
| query table (NULL / session): 50=1/1, 51=0/0, 52=0/0, 64=0/0, 70 -> 50/50, 82=1/1, 83 ok len 0 (first byte cleared) both, 85 -> 12018/87, 103 = 4 / 12016, 54..57 -> 12018/50 | D cases 0x32..0x39, 0x46, 0x53 + V |
