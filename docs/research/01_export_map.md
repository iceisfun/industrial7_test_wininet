# 01 - wininet.dll export map (Windows 10 x64, 19041)

Role: export cartographer. Every export of the reference `wininet.dll` is sorted into a behavioural family and
given a headless-testability tier, so test areas can be split without overlap and coverage can be checked
mechanically. Sources:

* `tools/wininet_exports.json` (export table of the reference binary: 327 entries).
* Corpus Explorer on docker1 (`/api/resolve?ref=wininet!ordinal:N`, `/api/function/wininet/<rva>`, `/asm`,
  `/decomp`, `/docs`, `/api/modules/<m>/imports`). Reference image: wininet.dll file version
  11.0.19041.2193, PDB `wininet.pdb` GUID 1A750296-FF73-0210-FC57-4B55140FF248 age 1, 7385 functions, all
  with decompilations.
* "doc" = the corpus has an exact Microsoft SDK reference page (`sdk-api`) for the export name.
* "mingw" = the name appears in the mingw-w64 `wininet.h`/`winineti.h`; `-` means the test must declare
  the prototype itself (`UDECL`/`UN`).

Everything marked "decomp" below was read from the reference disassembly/decompilation, not run. Hard
`CHECK`s built on it still need a Win10 VM pass (tests that disagree with the VM get downgraded, not the
VM).

## Headline facts

| fact | value |
|---|---|
| export entries | 327 (ordinal base 101, ordinals 101..427, no gaps) |
| named | 299 |
| ordinal-only (no name) | 28: 101-105, 108-112, 116-118, 120-123, 346, 401-403, 410, 411, 413, 420-423 |
| forwarders | 0 (every export is code inside wininet.dll) |
| exact SDK doc page | 191 of 327 |
| declared by mingw headers | 189 of 299 named (110 need a local prototype) |
| COMDAT-folded (several exports, one RVA) | 15 groups, see below |

### Shared-RVA groups (identical code folded by the linker)

These are not forwarders; `GetProcAddress` returns the same address for each name in a group. That is a
linker detail: an implementation may use separate functions. Tests may `t_note` the equality, but
must not `CHECK` it.

| RVA | exports | what the code does (decomp) |
|---|---|---|
| 0x138810 | `GopherCreateLocatorA/W`, `GopherFindFirstFileA/W`, `GopherGetAttributeA/W`, `GopherGetLocatorTypeA/W`, `GopherOpenFileA/W`, `InternetWriteFileExA/W`, `LoadUrlCacheContent` | `SetLastError(120 ERROR_CALL_NOT_IMPLEMENTED); return 0` |
| 0x0dabf0 | `DllInstall`, `InternetGetCertByURL`, `InternetGetCertByURLA`, `RunOnceUrlCache` | `return 0` (no SetLastError) |
| 0x0db0e0 | `RegisterUrlCacheNotification`, `UrlCacheServer`, #112 (`IsDuoStream`) | `return 1` |
| 0x1847f0 | `ShowCertificate`, `ShowClientAuthCerts`, `ParseX509EncodedCertificateForListBoxEntry` | `SetLastError(120); return 120` |
| 0x13c4f0 | #120, #121, #122, #123 (PDB name `GetP3PPolicy`) | `SetLastError(120); return 0xFF` |
| 0x167230 | `HttpCheckDavCompliance`, #104 | see stubs table |
| 13 A/plain pairs | `DeleteUrlCacheEntry`=`DeleteUrlCacheEntryA`, `InternetConfirmZoneCrossing`=`...A`, `InternetDial`=`InternetDialA`, `InternetGetConnectedStateEx`=`...ExA`, `InternetGetSecurityInfoByURL`=`...A`, `InternetGoOnline`=`...A`, `InternetSetDialState`=`...A`, `InternetSetStatusCallback`=`...A`, `InternetShowSecurityInfoByURL`=`...A`, `InternetTimeFromSystemTime`=`...A`, `InternetTimeToSystemTime`=`...A`, `SetUrlCacheEntryGroup`=`...A`, `UnlockUrlCacheEntryFile`=`...A` | the undecorated name is the ANSI entry point; a test should call the undecorated name with ANSI arguments |

## Ordinal-only exports (resolved through the corpus PDB)

Call them as `GetProcAddress(h, MAKEINTRESOURCEA(n))`. None is documented. "pin" means the behaviour is
fixed and can be asserted exactly once the VM confirms it.

| ord | PDB name | bytes | behaviour (decomp) | tier |
|---:|---|---:|---|:-:|
| 101 | DoConnectoidsExist | 269 | RAS enumeration (`RasEnumEntriesW`); `SetLastError(120)` if RAS is missing | E |
| 102 | GetDiskInfoA(path, *pdwClusterSize?, *free, *total) | 217 | `StringCchCopyA` + `GetDiskFreeSpaceExA`; FALSE for NULL/short path | H |
| 103 | PerformOperationOverUrlCacheA | 506 | loops `FindFirstUrlCacheEntryExA`/`Next` and calls a callback per entry | S |
| 104 | (= HttpCheckDavCompliance) | 184 | always FALSE: GLE 87 on NULL url/headers/out or non-NULL reserved, else GLE 12016 `ERROR_INTERNET_INVALID_OPERATION`; `*out=0` when out non-NULL | N pin |
| 105 | HttpCheckDavComplianceW | 184 | same as #104, wide | N pin |
| 108 | ImportCookieFileA | 137 | A->W wrapper of #110 | S |
| 109 | ExportCookieFileA | 153 | A->W wrapper of #111 | S |
| 110 | ImportCookieFileW | 1303 | parses a Netscape-style cookie file into the store | S |
| 111 | ExportCookieFileW | 1293 | writes the cookie store to a file | S |
| 112 | IsDuoStream (folded) | 6 | `return 1` | N pin |
| 116 | IsDomainLegalCookieDomainA | 300 | pure domain-match predicate (cookie Domain= legality) | H |
| 117 | IsDomainLegalCookieDomainW | 289 | W->A conversion then #116 | H |
| 118 | FindP3PPolicySymbol | 13 | NULL -> `-1`, else tail call into a symbol table lookup | N/H |
| 120-123 | GetP3PPolicy (folded, 4 ordinals) | 31 | `SetLastError(120); return 0xFF` | N pin |
| 346 | InternalInternetGetCookie | 6 | `return 0x103` (`ERROR_NO_MORE_ITEMS`); retired | N pin |
| 401 | ReadGuidsForConnectedNetworks | 68 | `return 0` (WPP trace only) | N pin |
| 402 | InternetAutoProxyGetProxyForUrl | 28 | `if (arg2) memset(arg2,0,0x28); return 0` | N pin |
| 403 | InternetAutoProxyOnSendRequestComplete | 412 | auto-proxy bookkeeping on a request handle | I |
| 410 | GetCacheServerConnection | 15 | `if (p) *p=NULL; return E_FAIL` | N pin |
| 411 | CreateCacheServerRpcBinding | 25 | `if (arg2) *arg2=NULL; return arg1 ? E_FAIL : E_INVALIDARG` | N pin |
| 413 | SetGlobalJetParameters | 6 | `return E_FAIL` | N pin |
| 420 | IsLanConnection | 64 | `WxIsLanConnection(int*)` | E |
| 421 | IsDialUpConnection | 66 | `WxIsDialUpConnection(int*)` | E |
| 422 | RegisterForNetworkChangeNotification | 64 | network-change registration | I |
| 423 | UnRegisterNetworkChangeNotification | 42 | pairs with #422 | I |

Note: the export table itself has no names for these ordinals; the names are PDB publics. An
implementation only needs the ordinal to resolve to code with the same behaviour.

## Fixed-behaviour stubs (named exports)

Retired features compiled down to constant behaviour. They are the cheapest exact checks in the corpus
(area suggestion: `stubs_retired`). Values are from the disassembly; confirm each on the VM before a hard
`CHECK`.

| export(s) | return | GetLastError |
|---|---|---|
| all 10 `Gopher*`, `InternetWriteFileExA/W`, `LoadUrlCacheContent` | 0 (FALSE/NULL) | 120 |
| `InternetFortezzaCommand`, `InternetQueryFortezzaStatus` | FALSE | 120 |
| `InternetSetDialState`, `...A`, `...W` | FALSE | 120 |
| `ShowCertificate`, `ShowClientAuthCerts`, `ParseX509EncodedCertificateForListBoxEntry` | 120 (DWORD) | 120 |
| `DeleteIE3Cache` | 120 (DWORD) | unchanged |
| `HttpCheckDavCompliance` (= #104) | FALSE | 87 or 12016 (see above) |
| `InternetGetCertByURL`, `InternetGetCertByURLA`, `RunOnceUrlCache`, `DllInstall` | 0 | unchanged |
| `UrlCacheServer`, `RegisterUrlCacheNotification` | 1 | unchanged |
| `InternetAutodialCallback` | void, does nothing | unchanged |
| `DispatchAPICall` | bare `ret`: RAX is garbage, assert nothing but "does not crash" | unchanged |
| `InternetAttemptConnect(dwReserved)` | 0 (`ERROR_SUCCESS`) when 0, else 87; never touches the network | unchanged |

"unchanged" means the stub does not call `SetLastError`; a test can seed a sentinel with `SetLastError`
and check it survives.

## Testability tiers

| tier | meaning | how to test |
|:-:|---|---|
| H | headless and deterministic: pure functions, or client behaviour against the in-process loopback servers | normal areas, hard CHECKs |
| S | headless, but touches per-user persistent state (URL cache, cookie jar, cache groups, AppCache) | unique `tmpPrefix+pid` URLs/domains, delete what was created, never enumerate-and-assert global contents |
| N | fixed-behaviour stub (decomp) | exact return + GLE, after VM confirmation |
| E | depends on the machine's network environment (RAS, WPAD/PAC, NLA connectivity, Passport) | parameter-validation negatives as CHECK, the success path only as `t_note` |
| X | changes global/per-user settings or deletes shared state (registry, cache limits, containers, per-site decisions) | only in `dx_<name>` areas that save and restore state |
| U | shows UI (cert viewers, zone-crossing and error dialogs) | only argument checks that fail before any window appears, or `FLAGS_ERROR_UI_FLAGS_NO_UI`; never a blocking dialog |
| I | internal / broker / COM plumbing used by urlmon, Edge legacy or the cache service | resolve-only plus documented COM contracts (`DllCanUnloadNow`, `DllGetClassObject` with a bogus CLSID) |

## Families

Totals: 327 entries = H 110, S 96, N 44, X 28, E 25, I 15, U 9.

| family | n | doc | tiers | suggested areas |
|---|---:|---:|---|---|
| URL - URL helpers, time and string formatters | 21 | 15 | H 21 | `url_crack`, `url_create`, `url_canon_combine`, `url_time`, `url_misc` |
| HANDLE - session / connect / OpenUrl / handle lifetime | 10 | 10 | H | `handle_session`, `openurl_http` |
| OPT - Query/SetOption(Ex) | 7 | 6 | H | `options_global`, `options_handle` |
| CB - status callbacks / async | 3 | 2 | H | `async_callback` |
| HTTP - request / send / headers / query info | 15 | 12 | H | `http_request`, `http_headers_wire`, `http_queryinfo`, `http_sendex_upload`, `http_redirect`, `http_auth` |
| IO - body reads/writes, data available, file pointer, lock | 11 | 11 | H | `http_body_io`, `http_chunked_gzip`, `http_lockfile` |
| WS - HttpWebSocket* | 6 | 0 | H | `websocket` (loopback upgrade server) |
| FTP | 25 | 23 | H | `ftp_session`, `ftp_files`, `ftp_dirs` (loopback FTP server) |
| COOKIE - cookies, cookie2, per-site decisions, P3P, privacy | 32 | 20 | S 15, H 7, N 6, X 4 | `cookie_api`, `cookie_wire`, `cookie_ex2`, `cookie_import_export`, `dx_cookie_persite` |
| CACHE - classic URL cache, groups, containers, config | 71 | 50 | S 53, X 15, N 3 | `cache_entry`, `cache_enum`, `cache_group`, `cache_stream`, `cache_http_integration`, `dx_cache_config`, `dx_cache_container` |
| CACHE2 - `UrlCache*` (newer cache API, undocumented) | 18 | 0 | S 13, X 5 | `cache_urlcache_api` |
| APPCACHE - HTML5 AppCache API (undocumented) | 18 | 0 | S 15, X 3 | `appcache_negative` (argument validation and empty-state queries) |
| PROXY - auto-proxy, bypass list, proxy info | 9 | 2 | E 5, H 2, X 1, N 1 | `proxy_bypass`, `proxy_autoproxy_negative`, `dx_proxy_settings` |
| CONN - connectivity, dial-up, online/offline | 21 | 15 | E 20, N 1 | `conn_state` (notes + negatives) |
| SEC - security info, cert viewers, zone crossing | 12 | 3 | U 8, H 3, I 1 | `sec_info_byurl` (with the schannel loopback server) |
| UI - InternetErrorDlg | 1 | 1 | U | `errordlg_noui` (NO_UI flags, argument checks) |
| DEP - dependency handles, page-load, HTTP push | 7 | 0 | I | resolve + NULL-argument negatives only |
| AUTH - Passport nexus | 2 | 0 | I | resolve-only |
| COM - Dll* entry points | 5 | 5 | I | `com_entry` |
| STUB - retired features with constant behaviour | 33 | 16 | N | `stubs_retired` |

### URL helpers (H)
`InternetCrackUrlA/W`, `InternetCreateUrlA/W`, `InternetCanonicalizeUrlA/W`, `InternetCombineUrlA/W`,
`InternetConvertUrlFromWireToWideChar` (undocumented; urlmon imports it; wrapper over
`...Internal(0,1,...)`), `_GetFileExtensionFromUrl` (undocumented: returns a Win32 code, not BOOL: 87 for
NULL/empty url, NULL buffer or `*pcch==0`; 2 when there is no extension; 122 with `*pcch = needed+1` when
the buffer is short; 0 on success), `InternetTimeFromSystemTime[A/W]`, `InternetTimeToSystemTime[A/W]`,
`InternetAlgIdToStringA/W` and `InternetSecurityProtocolToStringA/W` (undocumented table lookups:
`(id, buf, *pcch, reserved)`; reserved must be 0, `pcch` non-NULL, buf NULL is a size query; the protocol
table has 7 entries), `CreateMD5SSOHash` (documented; pure MD5 helper over a challenge and realm/target).
Richest pure family; the decomp of `InternetCrackUrlW` and `InternetCreateUrlW` (3.7 KB) is the oracle for
edge cases. WinHTTP has parallel `WinHttpCrackUrl/CreateUrl/TimeFromSystemTime/TimeToSystemTime`: useful
for side-by-side notes, never as an oracle for wininet (they differ in flags and escaping).

### Handle/session, options, callbacks (H)
`InternetOpenA/W`, `InternetConnectA/W`, `InternetOpenUrlA/W`, `InternetCloseHandle`,
`InternetGetLastResponseInfoA/W` (FTP response text), `InternetAttemptConnect`;
`InternetQueryOptionA/W` (A is 7.6 KB, W 2.5 KB), `InternetSetOptionA/W` (A is 12.7 KB: the option switch
lives here), `InternetSetOptionExA/W`, `InternetSetSecureLegacyServersAppCompat` (undocumented; flips a
global, no return value: resolve-only); `InternetSetStatusCallback[A]`, `InternetSetStatusCallbackW`.
Process-global options (proxy, `INTERNET_OPTION_SETTINGS_CHANGED`, `REFRESH`, per-server limits) belong in
`dx_*`; handle options and read-only global queries are H.

### HTTP request/response, headers, body IO (H)
`HttpOpenRequestA/W`, `HttpSendRequestA/W`, `HttpSendRequestExA/W`, `HttpEndRequestA/W`,
`HttpAddRequestHeadersA/W`, `HttpQueryInfoA/W`; `InternetReadFile`, `InternetReadFileExA/W`,
`InternetWriteFile`, `InternetQueryDataAvailable` (3.7 KB), `InternetSetFilePointer`,
`InternetLockRequestFile`, `InternetUnlockRequestFile`, `ResumeSuspendedDownload`, `InternetFindNextFileA/W`
(FTP find handles). These are the core of the corpus and all run against the loopback HTTP server with the
connection recorder (request line, header order and casing, Host, User-Agent, Accept, Cookie,
Authorization, Content-Length, chunked). Redirect, auth (Basic/NTLM/Negotiate through sspicli) and
credential behaviour are driven through these entry points plus options; there are no separate
redirect/credential exports except the internal `HttpGetServerCredentials`.
Undocumented HTTP extras: `HttpIsHostHstsEnabled(host, *pfEnabled)` (H: `*pf=0` first; NULL host or NULL
out returns 87 via `WX_WIN32_FROM_HR(E_INVALIDARG)`; a loopback host never learned via HSTS reads 0),
`HttpGetTunnelSocket` (I), `HttpGetServerCredentials` (I).

### WebSocket (H, undocumented)
`HttpWebSocketCompleteUpgrade`, `...Send`, `...Receive`, `...Close`, `...Shutdown`, `...QueryCloseStatus`.
Same shape as the documented WinHTTP WebSocket API (BOOL + SetLastError here, versus DWORD returns in
WinHTTP). Needs a loopback server that answers `101 Switching Protocols`; NULL-handle negatives first.

### FTP (H)
All 25 `Ftp*` (23 documented; `FtpGetFileEx`, `FtpPutFileEx` are the undocumented wide-path variants).
Against the in-process FTP server only. `FtpGetFileSize` is also imported by urlmon.

### Cookies (S/H/X/N)
Store API: `InternetGetCookieA/W` (thin wrappers over `...ExA/W`), `InternetGetCookieExA/W`,
`InternetSetCookieA/W`, `InternetSetCookieExA/W`, `InternetGetCookieEx2`, `InternetSetCookieEx2`,
`InternetFreeCookies` (Ex2 trio: documented; mingw lacks them). Per-site P3P decisions:
`InternetGet/Enum/SetPerSiteCookieDecisionA/W`, `InternetClearAllPerSiteCookieDecisions` (deletes every
subkey of the per-user decision key: always `dx_`). `PrivacyGetZonePreferenceW` (read: H),
`PrivacySetZonePreferenceW` (X). Ordinal-only: #108-#111 cookie file import/export, #116/#117 domain
legality predicate (pure), #118/#120-123/#346 retired P3P/cookie stubs. Cookies must use unique
`*.tmpPrefix+pid` hosts and be expired after the test; wire-level Cookie/Set-Cookie behaviour goes in an
HTTP area.

### URL cache (S/X)
Classic cache (71 including helpers): `Commit/Create/Delete/Retrieve/Unlock/Get/SetUrlCacheEntry*`,
`Find{First,Next}UrlCacheEntry[Ex]A/W`, `FindCloseUrlCache`, `ReadUrlCacheEntryStream[Ex]`,
`RetrieveUrlCacheEntryStreamA/W`, `UnlockUrlCacheEntryStream`, `IsUrlCacheEntryExpiredA/W`, groups
(`Create/DeleteUrlCacheGroup`, `Find{First,Next}UrlCacheGroup`, `Get/SetUrlCacheGroupAttributeA/W`,
`SetUrlCacheEntryGroup[A/W]`), containers (`Create/DeleteUrlCacheContainerA/W` have `winineti.h` SDK pages,
`Find{First,Next}UrlCacheContainerA/W` have none; mingw declares none of them), configuration and
global state (`Get/SetUrlCacheConfigInfoA/W`, `FreeUrlCacheSpaceA/W`, `Get/Set/IncrementUrlCacheHeaderData`,
`UpdateUrlCacheContentPath`, `CommitUrlCacheEntryBinaryBlob`, `GetUrlCacheEntryBinaryBlob`,
`CreateUrlCacheEntryExW`), ordinal helpers #102/#103/#410/#411/#413.
Newer `UrlCache*` API (18, undocumented, each a thin wrapper over `...Internal`): `UrlCacheFindFirstEntry`,
`FindNextEntry`, `GetEntryInfo`, `FreeEntryInfo`, `RetrieveEntryFile`, `RetrieveEntryStream`,
`ReadEntryStream`, `CloseEntryHandle`, `UpdateEntryExtraData`, `CheckEntriesExist`, `CreateContainer`,
`ContainerSetEntryMaximumAge`, `GetContentPaths`, `GetGlobalCacheSize`, `GetGlobalLimit`,
`SetGlobalLimit`, `FreeGlobalSpace`, `ReloadSettings`. The backing store is ESE (wininet imports 39
`esent!Jet*` functions, all delay-loaded) - an implementation detail tests must not depend on.
Entry-level operations on unique URLs are S; anything that changes limits, paths, containers or frees
space is X.

### AppCache (S/X, undocumented)
18 `AppCache*` exports, all thin wrappers over `...Internal` (urlmon imports `AppCacheCloseHandle`,
`DuplicateHandle`, `FreeGroupList`, `GetFallbackUrl`, `GetGroupList`, `Lookup`). No public prototypes, and the
corpus type index does not carry `_APP_CACHE_*` layouts: reconstruct from the decomp before testing more
than NULL-argument paths. Limit tests to argument
validation, empty-group queries and lookups of unique URLs that must miss; `AppCacheFreeSpace`,
`FreeIESpace`, `DeleteIEGroup` are X.

### Proxy / auto-proxy (E/H/X)
`DetectAutoProxyUrl` (WPAD: E), `InternetInitializeAutoProxyDll` (E), `InternetGetProxyForUrl` +
`InternetFreeProxyInfoList` (undocumented; the free function is H with a NULL/empty list),
`IsHostInProxyBypassList(scheme, host, cch)` (H, 3.2 KB: compares against the configured bypass list, so
only `<local>`/loopback-style results that hold for the default VM config are CHECKable),
`DeleteWpadCacheForNetworks` (X: `RegDeleteTreeW` under HKCU), `GetProxyDllInfo` (writes two internal
pointers, no return: I), #402, #403.

### Connectivity / dial-up / offline (E)
`InternetGetConnectedState`, `InternetGetConnectedStateEx[A/W]`, `InternetCheckConnectionA/W` (touches the
network unless pointed at a loopback URL), `InternetAutodial`, `InternetAutodialHangup`,
`InternetDial[A/W]`, `InternetHangUp`, `InternetGoOnline[A/W]`, ordinals #101, #401, #420-#423. Decomp gives
exact argument checks worth asserting: `InternetAutodial` rejects any flag outside the low 4 bits with
`ERROR_INVALID_PARAMETER`; `InternetGoOnline` rejects flags outside the low 2 bits; `InternetDial` with
`lpdwConnection == NULL` or non-zero reserved returns 87; `InternetHangUp` with non-zero reserved returns
87; with RAS unavailable the dial family returns `ERROR_CALL_NOT_IMPLEMENTED` (120) as a Win32 code or GLE.
The success paths depend on RAS/NLA and are `t_note` only.

### Security info and certificates (H/U)
`InternetGetSecurityInfoByURL[A/W]` (undocumented; `(url, PCCERT_CHAIN_CONTEXT*, DWORD *pdwSecureFlags)`; looks the URL's host up in the
per-process SSL security cache: unknown host gives FALSE + GLE 12028 `ERROR_INTERNET_ITEM_NOT_FOUND` (H),
after a TLS request to the schannel loopback server it returns a duplicated chain and the
`SECURITY_FLAG_*` subset `flags & 0x07A00000`), `InternetShowSecurityInfoByURL[A/W]`, `ShowSecurityInfo`,
`ShowX509EncodedCertificate` (all call `CryptUIDlgViewCertificateW`: U, never call with real arguments),
`InternetConfirmZoneCrossing[A/W]` (documented; can show UI: only the non-UI paths), `UrlZonesDetach`
(releases urlmon zone/security managers: I). `InternetErrorDlg` is the UI family; only
`FLAGS_ERROR_UI_FLAGS_NO_UI` and argument-check paths are safe.

### Dependency handles, push, Passport, COM (I)
`HttpOpenDependencyHandle`, `HttpCloseDependencyHandle`, `HttpDuplicateDependencyHandle`,
`HttpIndicatePageLoadComplete` (NULL -> `E_INVALIDARG` mapped to Win32), `HttpPushEnable`, `HttpPushWait`,
`HttpPushClose`: all urlmon-only plumbing, undocumented. `ForceNexusLookup`, `ForceNexusLookupExW`:
Passport nexus (network: never call the success path). `DllCanUnloadNow`, `DllGetClassObject`,
`DllRegisterServer`, `DllUnregisterServer` (never call: registration is system-wide), `DllInstall` (stub).

## Companion modules: consumers and helpers

Measured from the corpus import tables (`/api/modules/<m>/imports`). wininet imports nothing from
winhttp or schannel by name.

| module | relation to wininet | matters for the corpus because |
|---|---|---|
| urlmon.dll | biggest consumer: imports 73 wininet exports (core HTTP, cache, AppCache, dependency handles, HttpPush*, `HttpIsHostHstsEnabled`, `IsHostInProxyBypassList`, `InternetConvertUrlFromWireToWideChar`, `UrlCache*` find/free/create-container) and `sspicli!GetUserNameExW`; wininet imports back `CoInternetIsFeatureEnabledForUrl`, `CoInternetCreateSecurityManager`, `CoInternetCreateZoneManager` (zones, delay-loaded) | the undocumented exports urlmon uses are the ones an implementation cannot skip; `URLDownloadToFile`/`URLOpenStream` against loopback are an end-to-end consumer check (separate `urlmon_consumer` area) |
| shell32.dll, windows.storage.dll | import `CommitUrlCacheEntryW`, `CreateUrlCacheEntryW`, `InternetCrackUrlW`, `InternetCreateUrlW` | these four are the minimum for the shell; prioritise their edge cases |
| sspicli.dll | wininet imports 20: `AcquireCredentialsHandleA/W`, `InitializeSecurityContextA/W`, `DeleteSecurityContext`, `FreeCredentialsHandle`, `FreeContextBuffer`, `QueryContextAttributesExA/W`, `SetContextAttributesW`, `MakeSignature`, `SealMessage`, `UnsealMessage`, `EnumerateSecurityPackagesA`, `GetUserNameExA`, `SspiEncodeAuthIdentityAsStrings`, `SspiFreeAuthIdentity`, `SspiLocalFree`, `SeciAllocateAndSetCallTarget`, `SeciFreeCallContext` | TLS (schannel package) and NTLM/Negotiate/Digest auth all go through these; the test servers also use them on the accept side |
| schannel.dll | 36 exports, 24 of them forward to `SSPICLI.*`; the rest are legacy `Ssl*` helpers | reached only as the "Microsoft Unified Security Protocol Provider" package loaded by sspicli/lsass; nothing to test directly from this corpus |
| crypt32.dll | 25 delay-loaded imports (chain build/verify, store, `CertGetNameStringW`, `CryptProtectData`/`CryptUnprotectData` for stored credentials, `CryptProtectMemory`) | certificate errors (`ERROR_INTERNET_SEC_CERT_*`, `SECURITY_FLAG_IGNORE_*`) and the self-signed loopback cert (`CertCreateSelfSignCertificate`) |
| ws2_32.dll | 30 delay-loaded imports: `getaddrinfo`/`GetAddrInfoExW`, `WSASocketW`, `WSAIoctl`, `WSARecv`/`WSASend`, `WSAEventSelect` plus 20 by ordinal (classic BSD-style calls such as connect, closesocket, send, recv, setsockopt) | the wire behaviour tests rely on; the corpus servers use ws2_32 directly |
| winhttp.dll | not imported by wininet; separate stack with a parallel API (Open/Connect/OpenRequest, CrackUrl/CreateUrl, Time helpers, WebSocket, auto-proxy). Its own sspicli imports are identity helpers only | side-by-side `t_note` comparisons only; never an oracle. The WPAD/PAC service (`WinHttpAutoProxySvcMain`) also serves wininet auto-proxy over RPC, which is why the auto-proxy family is environment-dependent |
| others (delay-loaded) | `esent` (39, cache DB), `iertutil` (21, mostly by ordinal), `credui` (prompts), `cryptui` (cert dialogs), `bcrypt` (hashing, random), `iphlpapi` (network change), `rasapi32` (`RasEnumEntriesW`), `tokenbinding`, `wintrust`, `httpapi`, `powrprof` | explains which features are UI-bound (credui/cryptui) or environment-bound (rasapi32, iphlpapi) |

## Coverage guidance

* Mechanical coverage: `tools/coverage.py` scans `tools/wininet_exports.txt`, which holds named exports only,
  so the 28 ordinal-only entries must be tracked against the appendix by hand. Every export should be
  either exercised, or resolve-only (tiers I and U) with the reason recorded.
* Ordinal-only exports must be resolved by number, not name; a test that `REQUIRE`s them should
  `GetProcAddress(h, MAKEINTRESOURCEA(n))` and `t_note` the PDB name.
* Exports missing from mingw headers (110) need a local prototype; the decomp signatures above are the
  source, and PDB types are available for the documented structs.

## Appendix: all 327 exports

`doc`: Y = exact SDK page in the corpus. `mingw`: Y = declared in mingw `wininet.h`/`winineti.h`.
`tier`: see legend. `bytes`: size of the function at the export RVA (cold split parts excluded).

| ord | export | family | doc | mingw | tier | bytes | shares RVA with |
|---:|---|---|:-:|:-:|:-:|---:|---|
| 101 | `(ordinal-only) DoConnectoidsExist` | CONN | - | - | E | 269 |  |
| 102 | `(ordinal-only) GetDiskInfoA` | CACHE | - | - | S | 217 |  |
| 103 | `(ordinal-only) PerformOperationOverUrlCacheA` | CACHE | - | - | S | 506 |  |
| 104 | `(ordinal-only) HttpCheckDavCompliance` | STUB | - | - | N | 184 | HttpCheckDavCompliance |
| 105 | `(ordinal-only) HttpCheckDavComplianceW` | STUB | - | - | N | 184 |  |
| 106 | `AppCacheCheckManifest` | APPCACHE | - | - | S | 113 |  |
| 107 | `AppCacheCloseHandle` | APPCACHE | - | - | S | 42 |  |
| 108 | `(ordinal-only) ImportCookieFileA` | COOKIE | - | - | S | 137 |  |
| 109 | `(ordinal-only) ExportCookieFileA` | COOKIE | - | - | S | 153 |  |
| 110 | `(ordinal-only) ImportCookieFileW` | COOKIE | - | - | S | 1303 |  |
| 111 | `(ordinal-only) ExportCookieFileW` | COOKIE | - | - | S | 1293 |  |
| 112 | `(ordinal-only) IsDuoStream` | STUB | - | - | N | 6 | RegisterUrlCacheNotification,UrlCacheServer |
| 113 | `AppCacheCreateAndCommitFile` | APPCACHE | - | - | S | 73 |  |
| 114 | `AppCacheDeleteGroup` | APPCACHE | - | - | S | 62 |  |
| 115 | `AppCacheDeleteIEGroup` | APPCACHE | - | - | X | 62 |  |
| 116 | `(ordinal-only) IsDomainLegalCookieDomainA` | COOKIE | - | - | H | 300 |  |
| 117 | `(ordinal-only) IsDomainLegalCookieDomainW` | COOKIE | - | - | H | 289 |  |
| 118 | `(ordinal-only) FindP3PPolicySymbol` | COOKIE | - | - | N | 13 |  |
| 119 | `AppCacheDuplicateHandle` | APPCACHE | - | - | S | 914 |  |
| 120 | `(ordinal-only) GetP3PPolicy` | COOKIE | - | - | N | 31 | #121,#122,#123 |
| 121 | `(ordinal-only) GetP3PPolicy` | COOKIE | - | - | N | 31 | #120,#122,#123 |
| 122 | `(ordinal-only) GetP3PPolicy` | COOKIE | - | - | N | 31 | #120,#121,#123 |
| 123 | `(ordinal-only) GetP3PPolicy` | COOKIE | - | - | N | 31 | #120,#121,#122 |
| 124 | `AppCacheFinalize` | APPCACHE | - | - | S | 64 |  |
| 125 | `AppCacheFreeDownloadList` | APPCACHE | - | - | S | 207 |  |
| 126 | `AppCacheFreeGroupList` | APPCACHE | - | - | S | 129 |  |
| 127 | `AppCacheFreeIESpace` | APPCACHE | - | - | X | 62 |  |
| 128 | `AppCacheFreeSpace` | APPCACHE | - | - | X | 62 |  |
| 129 | `AppCacheGetDownloadList` | APPCACHE | - | - | S | 64 |  |
| 130 | `AppCacheGetFallbackUrl` | APPCACHE | - | - | S | 64 |  |
| 131 | `AppCacheGetGroupList` | APPCACHE | - | - | S | 64 |  |
| 132 | `AppCacheGetIEGroupList` | APPCACHE | - | - | S | 64 |  |
| 133 | `AppCacheGetInfo` | APPCACHE | - | - | S | 64 |  |
| 134 | `AppCacheGetManifestUrl` | APPCACHE | - | - | S | 64 |  |
| 135 | `AppCacheLookup` | APPCACHE | - | - | S | 64 |  |
| 136 | `CommitUrlCacheEntryA` | CACHE | Y | Y | S | 768 |  |
| 137 | `CommitUrlCacheEntryBinaryBlob` | CACHE | - | - | S | 88 |  |
| 138 | `CommitUrlCacheEntryW` | CACHE | Y | Y | S | 708 |  |
| 139 | `CreateMD5SSOHash` | URL | Y | Y | H | 557 |  |
| 140 | `CreateUrlCacheContainerA` | CACHE | Y | - | X | 753 |  |
| 141 | `CreateUrlCacheContainerW` | CACHE | Y | - | X | 567 |  |
| 142 | `CreateUrlCacheEntryA` | CACHE | Y | Y | S | 721 |  |
| 143 | `CreateUrlCacheEntryExW` | CACHE | - | - | S | 567 |  |
| 144 | `CreateUrlCacheEntryW` | CACHE | Y | Y | S | 27 |  |
| 145 | `CreateUrlCacheGroup` | CACHE | Y | Y | S | 284 |  |
| 146 | `DeleteIE3Cache` | STUB | - | Y | N | 6 |  |
| 147 | `DeleteUrlCacheContainerA` | CACHE | Y | - | X | 311 |  |
| 148 | `DeleteUrlCacheContainerW` | CACHE | Y | - | X | 298 |  |
| 149 | `DeleteUrlCacheEntry` | CACHE | Y | Y | S | 353 | DeleteUrlCacheEntryA |
| 150 | `DeleteUrlCacheEntryA` | CACHE | Y | Y | S | 353 | DeleteUrlCacheEntry |
| 151 | `DeleteUrlCacheEntryW` | CACHE | Y | Y | S | 375 |  |
| 152 | `DeleteUrlCacheGroup` | CACHE | Y | Y | S | 248 |  |
| 153 | `DeleteWpadCacheForNetworks` | PROXY | - | - | X | 388 |  |
| 154 | `DetectAutoProxyUrl` | PROXY | Y | Y | E | 330 |  |
| 155 | `DispatchAPICall` | STUB | - | - | N | 3 |  |
| 156 | `DllCanUnloadNow` | COM | Y | - | I | 37 |  |
| 157 | `DllGetClassObject` | COM | Y | - | I | 114 |  |
| 158 | `DllInstall` | COM | Y | - | I | 3 | InternetGetCertByURL,InternetGetCertByURLA,RunOnceUrlCache |
| 159 | `DllRegisterServer` | COM | Y | - | I | 51 |  |
| 160 | `DllUnregisterServer` | COM | Y | - | I | 51 |  |
| 161 | `FindCloseUrlCache` | CACHE | Y | Y | S | 278 |  |
| 162 | `FindFirstUrlCacheContainerA` | CACHE | - | - | X | 459 |  |
| 163 | `FindFirstUrlCacheContainerW` | CACHE | - | - | X | 518 |  |
| 164 | `FindFirstUrlCacheEntryA` | CACHE | Y | Y | S | 372 |  |
| 165 | `FindFirstUrlCacheEntryExA` | CACHE | Y | Y | S | 514 |  |
| 166 | `FindFirstUrlCacheEntryExW` | CACHE | Y | Y | S | 441 |  |
| 167 | `FindFirstUrlCacheEntryW` | CACHE | Y | Y | S | 372 |  |
| 168 | `FindFirstUrlCacheGroup` | CACHE | Y | Y | S | 325 |  |
| 169 | `FindNextUrlCacheContainerA` | CACHE | - | - | X | 383 |  |
| 170 | `FindNextUrlCacheContainerW` | CACHE | - | - | X | 455 |  |
| 171 | `FindNextUrlCacheEntryA` | CACHE | Y | Y | S | 419 |  |
| 172 | `FindNextUrlCacheEntryExA` | CACHE | Y | Y | S | 1140 |  |
| 173 | `FindNextUrlCacheEntryExW` | CACHE | Y | Y | S | 471 |  |
| 174 | `FindNextUrlCacheEntryW` | CACHE | Y | Y | S | 450 |  |
| 175 | `FindNextUrlCacheGroup` | CACHE | Y | Y | S | 283 |  |
| 176 | `ForceNexusLookup` | AUTH | - | - | I | 66 |  |
| 177 | `ForceNexusLookupExW` | AUTH | - | - | I | 126 |  |
| 178 | `FreeUrlCacheSpaceA` | CACHE | Y | - | X | 598 |  |
| 179 | `FreeUrlCacheSpaceW` | CACHE | Y | - | X | 249 |  |
| 180 | `FtpCommandA` | FTP | Y | Y | H | 222 |  |
| 181 | `FtpCommandW` | FTP | Y | Y | H | 425 |  |
| 182 | `FtpCreateDirectoryA` | FTP | Y | Y | H | 151 |  |
| 183 | `FtpCreateDirectoryW` | FTP | Y | Y | H | 373 |  |
| 184 | `FtpDeleteFileA` | FTP | Y | Y | H | 151 |  |
| 185 | `FtpDeleteFileW` | FTP | Y | Y | H | 373 |  |
| 186 | `FtpFindFirstFileA` | FTP | Y | Y | H | 222 |  |
| 187 | `FtpFindFirstFileW` | FTP | Y | Y | H | 466 |  |
| 188 | `FtpGetCurrentDirectoryA` | FTP | Y | Y | H | 185 |  |
| 189 | `FtpGetCurrentDirectoryW` | FTP | Y | Y | H | 420 |  |
| 190 | `FtpGetFileA` | FTP | Y | Y | H | 595 |  |
| 191 | `FtpGetFileEx` | FTP | - | Y | H | 425 |  |
| 192 | `FtpGetFileSize` | FTP | Y | Y | H | 623 |  |
| 193 | `FtpGetFileW` | FTP | Y | Y | H | 252 |  |
| 194 | `FtpOpenFileA` | FTP | Y | Y | H | 217 |  |
| 195 | `FtpOpenFileW` | FTP | Y | Y | H | 136 |  |
| 196 | `FtpPutFileA` | FTP | Y | Y | H | 551 |  |
| 197 | `FtpPutFileEx` | FTP | - | Y | H | 381 |  |
| 198 | `FtpPutFileW` | FTP | Y | Y | H | 206 |  |
| 199 | `FtpRemoveDirectoryA` | FTP | Y | Y | H | 151 |  |
| 200 | `FtpRemoveDirectoryW` | FTP | Y | Y | H | 361 |  |
| 201 | `FtpRenameFileA` | FTP | Y | Y | H | 171 |  |
| 202 | `FtpRenameFileW` | FTP | Y | Y | H | 575 |  |
| 203 | `FtpSetCurrentDirectoryA` | FTP | Y | Y | H | 151 |  |
| 204 | `FtpSetCurrentDirectoryW` | FTP | Y | Y | H | 361 |  |
| 205 | `GetProxyDllInfo` | PROXY | - | - | E | 21 |  |
| 206 | `GetUrlCacheConfigInfoA` | CACHE | Y | Y | S | 668 |  |
| 207 | `GetUrlCacheConfigInfoW` | CACHE | Y | Y | S | 271 |  |
| 208 | `GetUrlCacheEntryBinaryBlob` | CACHE | - | - | S | 103 |  |
| 209 | `GetUrlCacheEntryInfoA` | CACHE | Y | Y | S | 447 |  |
| 210 | `GetUrlCacheEntryInfoExA` | CACHE | Y | Y | S | 580 |  |
| 211 | `GetUrlCacheEntryInfoExW` | CACHE | Y | Y | S | 3370 |  |
| 212 | `GetUrlCacheEntryInfoW` | CACHE | Y | Y | S | 3121 |  |
| 213 | `GetUrlCacheGroupAttributeA` | CACHE | Y | Y | S | 576 |  |
| 214 | `GetUrlCacheGroupAttributeW` | CACHE | Y | Y | S | 541 |  |
| 215 | `GetUrlCacheHeaderData` | CACHE | - | - | S | 393 |  |
| 216 | `GopherCreateLocatorA` | STUB | Y | Y | N | 28 | GopherCreateLocatorW,GopherFindFirstFileA,GopherFindFirstFileW,GopherGetAttributeA... |
| 217 | `GopherCreateLocatorW` | STUB | Y | Y | N | 28 | GopherCreateLocatorA,GopherFindFirstFileA,GopherFindFirstFileW,GopherGetAttributeA... |
| 218 | `GopherFindFirstFileA` | STUB | Y | Y | N | 28 | GopherCreateLocatorA,GopherCreateLocatorW,GopherFindFirstFileW,GopherGetAttributeA... |
| 219 | `GopherFindFirstFileW` | STUB | Y | Y | N | 28 | GopherCreateLocatorA,GopherCreateLocatorW,GopherFindFirstFileA,GopherGetAttributeA... |
| 220 | `GopherGetAttributeA` | STUB | Y | Y | N | 28 | GopherCreateLocatorA,GopherCreateLocatorW,GopherFindFirstFileA,GopherFindFirstFileW... |
| 221 | `GopherGetAttributeW` | STUB | Y | Y | N | 28 | GopherCreateLocatorA,GopherCreateLocatorW,GopherFindFirstFileA,GopherFindFirstFileW... |
| 222 | `GopherGetLocatorTypeA` | STUB | Y | Y | N | 28 | GopherCreateLocatorA,GopherCreateLocatorW,GopherFindFirstFileA,GopherFindFirstFileW... |
| 223 | `GopherGetLocatorTypeW` | STUB | Y | Y | N | 28 | GopherCreateLocatorA,GopherCreateLocatorW,GopherFindFirstFileA,GopherFindFirstFileW... |
| 224 | `GopherOpenFileA` | STUB | Y | Y | N | 28 | GopherCreateLocatorA,GopherCreateLocatorW,GopherFindFirstFileA,GopherFindFirstFileW... |
| 225 | `GopherOpenFileW` | STUB | Y | Y | N | 28 | GopherCreateLocatorA,GopherCreateLocatorW,GopherFindFirstFileA,GopherFindFirstFileW... |
| 226 | `HttpAddRequestHeadersA` | HTTP | Y | Y | H | 1390 |  |
| 227 | `HttpAddRequestHeadersW` | HTTP | Y | Y | H | 349 |  |
| 228 | `HttpCheckDavCompliance` | STUB | - | - | N | 184 | #104 |
| 229 | `HttpCloseDependencyHandle` | DEP | - | - | I | 174 |  |
| 230 | `HttpDuplicateDependencyHandle` | DEP | - | - | I | 346 |  |
| 231 | `HttpEndRequestA` | HTTP | Y | Y | H | 275 |  |
| 232 | `HttpEndRequestW` | HTTP | Y | Y | H | 293 |  |
| 233 | `HttpGetServerCredentials` | HTTP | - | - | H | 64 |  |
| 234 | `HttpGetTunnelSocket` | HTTP | - | - | H | 225 |  |
| 235 | `HttpIndicatePageLoadComplete` | DEP | - | - | I | 191 |  |
| 236 | `HttpIsHostHstsEnabled` | HTTP | - | - | H | 227 |  |
| 237 | `HttpOpenDependencyHandle` | DEP | - | - | I | 64 |  |
| 238 | `HttpOpenRequestA` | HTTP | Y | Y | H | 180 |  |
| 239 | `HttpOpenRequestW` | HTTP | Y | Y | H | 2129 |  |
| 240 | `HttpPushClose` | DEP | - | - | I | 145 |  |
| 241 | `HttpPushEnable` | DEP | - | - | I | 62 |  |
| 242 | `HttpPushWait` | DEP | - | - | I | 62 |  |
| 243 | `HttpQueryInfoA` | HTTP | Y | Y | H | 2175 |  |
| 244 | `HttpQueryInfoW` | HTTP | Y | Y | H | 1412 |  |
| 245 | `HttpSendRequestA` | HTTP | Y | Y | H | 127 |  |
| 246 | `HttpSendRequestExA` | HTTP | Y | Y | H | 358 |  |
| 247 | `HttpSendRequestExW` | HTTP | Y | Y | H | 536 |  |
| 248 | `HttpSendRequestW` | HTTP | Y | Y | H | 451 |  |
| 249 | `HttpWebSocketClose` | WS | - | - | H | 284 |  |
| 250 | `HttpWebSocketCompleteUpgrade` | WS | - | - | H | 189 |  |
| 251 | `HttpWebSocketQueryCloseStatus` | WS | - | - | H | 295 |  |
| 252 | `HttpWebSocketReceive` | WS | - | - | H | 299 |  |
| 253 | `HttpWebSocketSend` | WS | - | - | H | 282 |  |
| 254 | `HttpWebSocketShutdown` | WS | - | - | H | 284 |  |
| 255 | `IncrementUrlCacheHeaderData` | CACHE | - | Y | X | 296 |  |
| 256 | `InternetAlgIdToStringA` | URL | - | - | H | 470 |  |
| 257 | `InternetAlgIdToStringW` | URL | - | - | H | 470 |  |
| 258 | `InternetAttemptConnect` | HANDLE | Y | Y | H | 83 |  |
| 259 | `InternetAutodial` | CONN | Y | Y | E | 173 |  |
| 260 | `InternetAutodialCallback` | STUB | - | - | N | 69 |  |
| 261 | `InternetAutodialHangup` | CONN | Y | Y | E | 165 |  |
| 262 | `InternetCanonicalizeUrlA` | URL | Y | Y | H | 270 |  |
| 263 | `InternetCanonicalizeUrlW` | URL | Y | Y | H | 270 |  |
| 264 | `InternetCheckConnectionA` | CONN | Y | Y | E | 1247 |  |
| 265 | `InternetCheckConnectionW` | CONN | Y | Y | E | 249 |  |
| 266 | `InternetClearAllPerSiteCookieDecisions` | COOKIE | Y | Y | X | 5 |  |
| 267 | `InternetCloseHandle` | HANDLE | Y | Y | H | 69 |  |
| 268 | `InternetCombineUrlA` | URL | Y | Y | H | 285 |  |
| 269 | `InternetCombineUrlW` | URL | Y | Y | H | 317 |  |
| 270 | `InternetConfirmZoneCrossing` | SEC | Y | Y | U | 176 | InternetConfirmZoneCrossingA |
| 271 | `InternetConfirmZoneCrossingA` | SEC | Y | Y | U | 176 | InternetConfirmZoneCrossing |
| 272 | `InternetConfirmZoneCrossingW` | SEC | Y | Y | U | 197 |  |
| 273 | `InternetConnectA` | HANDLE | Y | Y | H | 473 |  |
| 274 | `InternetConnectW` | HANDLE | Y | Y | H | 1577 |  |
| 275 | `InternetConvertUrlFromWireToWideChar` | URL | - | - | H | 142 |  |
| 276 | `InternetCrackUrlA` | URL | Y | Y | H | 169 |  |
| 277 | `InternetCrackUrlW` | URL | Y | Y | H | 1723 |  |
| 278 | `InternetCreateUrlA` | URL | Y | Y | H | 146 |  |
| 279 | `InternetCreateUrlW` | URL | Y | Y | H | 3755 |  |
| 280 | `InternetDial` | CONN | Y | Y | E | 191 | InternetDialA |
| 281 | `InternetDialA` | CONN | Y | Y | E | 191 | InternetDial |
| 282 | `InternetDialW` | CONN | Y | Y | E | 191 |  |
| 283 | `InternetEnumPerSiteCookieDecisionA` | COOKIE | Y | Y | H | 104 |  |
| 284 | `InternetEnumPerSiteCookieDecisionW` | COOKIE | Y | Y | H | 249 |  |
| 285 | `InternetErrorDlg` | UI | Y | Y | U | 1654 |  |
| 286 | `InternetFindNextFileA` | IO | Y | Y | H | 87 |  |
| 287 | `InternetFindNextFileW` | IO | Y | Y | H | 342 |  |
| 288 | `InternetFortezzaCommand` | STUB | - | - | N | 96 |  |
| 289 | `InternetFreeCookies` | COOKIE | Y | - | S | 42 |  |
| 290 | `InternetFreeProxyInfoList` | PROXY | - | - | H | 144 |  |
| 291 | `InternetGetCertByURL` | STUB | - | - | N | 3 | DllInstall,InternetGetCertByURLA,RunOnceUrlCache |
| 292 | `InternetGetCertByURLA` | STUB | - | - | N | 3 | DllInstall,InternetGetCertByURL,RunOnceUrlCache |
| 293 | `InternetGetConnectedState` | CONN | Y | Y | E | 173 |  |
| 294 | `InternetGetConnectedStateEx` | CONN | Y | Y | E | 289 | InternetGetConnectedStateExA |
| 295 | `InternetGetConnectedStateExA` | CONN | Y | Y | E | 289 | InternetGetConnectedStateEx |
| 296 | `InternetGetConnectedStateExW` | CONN | Y | Y | E | 734 |  |
| 297 | `InternetGetCookieA` | COOKIE | Y | Y | S | 27 |  |
| 298 | `InternetGetCookieEx2` | COOKIE | Y | - | S | 77 |  |
| 299 | `InternetGetCookieExA` | COOKIE | Y | Y | S | 834 |  |
| 300 | `InternetGetCookieExW` | COOKIE | Y | Y | S | 888 |  |
| 301 | `InternetGetCookieW` | COOKIE | Y | Y | S | 25 |  |
| 302 | `InternetGetLastResponseInfoA` | HANDLE | Y | Y | H | 431 |  |
| 303 | `InternetGetLastResponseInfoW` | HANDLE | Y | Y | H | 454 |  |
| 304 | `InternetGetPerSiteCookieDecisionA` | COOKIE | Y | Y | H | 80 |  |
| 305 | `InternetGetPerSiteCookieDecisionW` | COOKIE | Y | Y | H | 163 |  |
| 306 | `InternetGetProxyForUrl` | PROXY | - | - | E | 62 |  |
| 307 | `InternetGetSecurityInfoByURL` | SEC | - | Y | H | 265 | InternetGetSecurityInfoByURLA |
| 308 | `InternetGetSecurityInfoByURLA` | SEC | - | Y | H | 265 | InternetGetSecurityInfoByURL |
| 309 | `InternetGetSecurityInfoByURLW` | SEC | - | Y | H | 238 |  |
| 310 | `InternetGoOnline` | CONN | Y | Y | E | 173 | InternetGoOnlineA |
| 311 | `InternetGoOnlineA` | CONN | Y | Y | E | 173 | InternetGoOnline |
| 312 | `InternetGoOnlineW` | CONN | Y | Y | E | 183 |  |
| 313 | `InternetHangUp` | CONN | Y | Y | E | 142 |  |
| 314 | `InternetInitializeAutoProxyDll` | PROXY | Y | Y | E | 885 |  |
| 315 | `InternetLockRequestFile` | IO | Y | Y | H | 1058 |  |
| 316 | `InternetOpenA` | HANDLE | Y | Y | H | 180 |  |
| 317 | `InternetOpenUrlA` | HANDLE | Y | Y | H | 142 |  |
| 318 | `InternetOpenUrlW` | HANDLE | Y | Y | H | 459 |  |
| 319 | `InternetOpenW` | HANDLE | Y | Y | H | 984 |  |
| 320 | `InternetQueryDataAvailable` | IO | Y | Y | H | 3680 |  |
| 321 | `InternetQueryFortezzaStatus` | STUB | - | Y | N | 89 |  |
| 322 | `InternetQueryOptionA` | OPT | Y | Y | H | 7593 |  |
| 323 | `InternetQueryOptionW` | OPT | Y | Y | H | 2482 |  |
| 324 | `InternetReadFile` | IO | Y | Y | H | 116 |  |
| 325 | `InternetReadFileExA` | IO | Y | Y | H | 1134 |  |
| 326 | `InternetReadFileExW` | IO | Y | Y | H | 287 |  |
| 327 | `InternetSecurityProtocolToStringA` | URL | - | - | H | 365 |  |
| 328 | `InternetSecurityProtocolToStringW` | URL | - | - | H | 365 |  |
| 329 | `InternetSetCookieA` | COOKIE | Y | Y | S | 33 |  |
| 330 | `InternetSetCookieEx2` | COOKIE | Y | - | S | 77 |  |
| 331 | `InternetSetCookieExA` | COOKIE | Y | Y | S | 155 |  |
| 332 | `InternetSetCookieExW` | COOKIE | Y | Y | S | 488 |  |
| 333 | `InternetSetCookieW` | COOKIE | Y | Y | S | 464 |  |
| 334 | `InternetSetDialState` | STUB | Y | Y | N | 86 | InternetSetDialStateA |
| 335 | `InternetSetDialStateA` | STUB | Y | Y | N | 86 | InternetSetDialState |
| 336 | `InternetSetDialStateW` | STUB | Y | Y | N | 86 |  |
| 337 | `InternetSetFilePointer` | IO | Y | Y | H | 453 |  |
| 338 | `InternetSetOptionA` | OPT | Y | Y | H | 12751 |  |
| 339 | `InternetSetOptionExA` | OPT | Y | Y | H | 242 |  |
| 340 | `InternetSetOptionExW` | OPT | Y | Y | H | 243 |  |
| 341 | `InternetSetOptionW` | OPT | Y | Y | H | 2866 |  |
| 342 | `InternetSetPerSiteCookieDecisionA` | COOKIE | Y | Y | X | 151 |  |
| 343 | `InternetSetPerSiteCookieDecisionW` | COOKIE | Y | Y | X | 156 |  |
| 344 | `InternetSetSecureLegacyServersAppCompat` | OPT | - | - | H | 28 |  |
| 345 | `InternetSetStatusCallback` | CB | Y | Y | H | 173 | InternetSetStatusCallbackA |
| 346 | `(ordinal-only) InternalInternetGetCookie` | COOKIE | - | - | N | 6 |  |
| 347 | `InternetSetStatusCallbackA` | CB | Y | Y | H | 173 | InternetSetStatusCallback |
| 348 | `InternetSetStatusCallbackW` | CB | - | Y | H | 176 |  |
| 349 | `InternetShowSecurityInfoByURL` | SEC | - | - | U | 225 | InternetShowSecurityInfoByURLA |
| 350 | `InternetShowSecurityInfoByURLA` | SEC | - | - | U | 225 | InternetShowSecurityInfoByURL |
| 351 | `InternetShowSecurityInfoByURLW` | SEC | - | - | U | 242 |  |
| 352 | `InternetTimeFromSystemTime` | URL | Y | Y | H | 332 | InternetTimeFromSystemTimeA |
| 353 | `InternetTimeFromSystemTimeA` | URL | Y | Y | H | 332 | InternetTimeFromSystemTime |
| 354 | `InternetTimeFromSystemTimeW` | URL | Y | Y | H | 305 |  |
| 355 | `InternetTimeToSystemTime` | URL | Y | Y | H | 64 | InternetTimeToSystemTimeA |
| 356 | `InternetTimeToSystemTimeA` | URL | Y | Y | H | 64 | InternetTimeToSystemTime |
| 357 | `InternetTimeToSystemTimeW` | URL | Y | Y | H | 250 |  |
| 358 | `InternetUnlockRequestFile` | IO | Y | Y | H | 747 |  |
| 359 | `InternetWriteFile` | IO | Y | Y | H | 116 |  |
| 360 | `InternetWriteFileExA` | STUB | Y | - | N | 28 | GopherCreateLocatorA,GopherCreateLocatorW,GopherFindFirstFileA,GopherFindFirstFileW... |
| 361 | `InternetWriteFileExW` | STUB | Y | - | N | 28 | GopherCreateLocatorA,GopherCreateLocatorW,GopherFindFirstFileA,GopherFindFirstFileW... |
| 362 | `IsHostInProxyBypassList` | PROXY | - | Y | H | 3219 |  |
| 363 | `IsUrlCacheEntryExpiredA` | CACHE | - | Y | S | 333 |  |
| 364 | `IsUrlCacheEntryExpiredW` | CACHE | - | Y | S | 352 |  |
| 365 | `LoadUrlCacheContent` | STUB | Y | - | N | 28 | GopherCreateLocatorA,GopherCreateLocatorW,GopherFindFirstFileA,GopherFindFirstFileW... |
| 366 | `ParseX509EncodedCertificateForListBoxEntry` | STUB | - | Y | N | 31 | ShowCertificate,ShowClientAuthCerts |
| 367 | `PrivacyGetZonePreferenceW` | COOKIE | Y | Y | H | 1401 |  |
| 368 | `PrivacySetZonePreferenceW` | COOKIE | Y | Y | X | 698 |  |
| 369 | `ReadUrlCacheEntryStream` | CACHE | Y | Y | S | 282 |  |
| 370 | `ReadUrlCacheEntryStreamEx` | CACHE | - | - | S | 281 |  |
| 371 | `RegisterUrlCacheNotification` | STUB | - | - | N | 6 | #112,UrlCacheServer |
| 372 | `ResumeSuspendedDownload` | IO | Y | Y | H | 208 |  |
| 373 | `RetrieveUrlCacheEntryFileA` | CACHE | Y | Y | S | 533 |  |
| 374 | `RetrieveUrlCacheEntryFileW` | CACHE | Y | Y | S | 542 |  |
| 375 | `RetrieveUrlCacheEntryStreamA` | CACHE | Y | Y | S | 562 |  |
| 376 | `RetrieveUrlCacheEntryStreamW` | CACHE | Y | Y | S | 571 |  |
| 377 | `RunOnceUrlCache` | STUB | - | - | N | 3 | DllInstall,InternetGetCertByURL,InternetGetCertByURLA |
| 378 | `SetUrlCacheConfigInfoA` | CACHE | - | Y | X | 332 |  |
| 379 | `SetUrlCacheConfigInfoW` | CACHE | - | Y | X | 276 |  |
| 380 | `SetUrlCacheEntryGroup` | CACHE | Y | Y | S | 487 | SetUrlCacheEntryGroupA |
| 381 | `SetUrlCacheEntryGroupA` | CACHE | Y | Y | S | 487 | SetUrlCacheEntryGroup |
| 382 | `SetUrlCacheEntryGroupW` | CACHE | Y | Y | S | 505 |  |
| 383 | `SetUrlCacheEntryInfoA` | CACHE | Y | Y | S | 566 |  |
| 384 | `SetUrlCacheEntryInfoW` | CACHE | Y | Y | S | 506 |  |
| 385 | `SetUrlCacheGroupAttributeA` | CACHE | Y | Y | S | 522 |  |
| 386 | `SetUrlCacheGroupAttributeW` | CACHE | Y | Y | S | 477 |  |
| 387 | `SetUrlCacheHeaderData` | CACHE | - | - | X | 303 |  |
| 388 | `ShowCertificate` | STUB | - | - | N | 31 | ParseX509EncodedCertificateForListBoxEntry,ShowClientAuthCerts |
| 389 | `ShowClientAuthCerts` | STUB | - | - | N | 31 | ParseX509EncodedCertificateForListBoxEntry,ShowCertificate |
| 390 | `ShowSecurityInfo` | SEC | - | - | U | 346 |  |
| 391 | `ShowX509EncodedCertificate` | SEC | - | - | U | 97 |  |
| 392 | `UnlockUrlCacheEntryFile` | CACHE | Y | Y | S | 309 | UnlockUrlCacheEntryFileA |
| 393 | `UnlockUrlCacheEntryFileA` | CACHE | Y | Y | S | 309 | UnlockUrlCacheEntryFile |
| 394 | `UnlockUrlCacheEntryFileW` | CACHE | Y | Y | S | 318 |  |
| 395 | `UnlockUrlCacheEntryStream` | CACHE | Y | Y | S | 302 |  |
| 396 | `UpdateUrlCacheContentPath` | CACHE | - | - | X | 330 |  |
| 397 | `UrlCacheCheckEntriesExist` | CACHE2 | - | - | S | 62 |  |
| 398 | `UrlCacheCloseEntryHandle` | CACHE2 | - | - | S | 47 |  |
| 399 | `UrlCacheContainerSetEntryMaximumAge` | CACHE2 | - | - | X | 62 |  |
| 400 | `UrlCacheCreateContainer` | CACHE2 | - | - | X | 75 |  |
| 401 | `(ordinal-only) ReadGuidsForConnectedNetworks` | CONN | - | - | N | 68 |  |
| 402 | `(ordinal-only) InternetAutoProxyGetProxyForUrl` | PROXY | - | - | N | 28 |  |
| 403 | `(ordinal-only) InternetAutoProxyOnSendRequestComplete` | PROXY | - | - | E | 412 |  |
| 404 | `UrlCacheFindFirstEntry` | CACHE2 | - | - | S | 90 |  |
| 405 | `UrlCacheFindNextEntry` | CACHE2 | - | - | S | 64 |  |
| 406 | `UrlCacheFreeEntryInfo` | CACHE2 | - | - | S | 100 |  |
| 407 | `UrlCacheFreeGlobalSpace` | CACHE2 | - | - | X | 224 |  |
| 408 | `UrlCacheGetContentPaths` | CACHE2 | - | - | S | 62 |  |
| 409 | `UrlCacheGetEntryInfo` | CACHE2 | - | - | S | 64 |  |
| 410 | `(ordinal-only) GetCacheServerConnection` | CACHE | - | - | N | 15 |  |
| 411 | `(ordinal-only) CreateCacheServerRpcBinding` | CACHE | - | - | N | 25 |  |
| 412 | `UrlCacheGetGlobalCacheSize` | CACHE2 | - | - | S | 257 |  |
| 413 | `(ordinal-only) SetGlobalJetParameters` | CACHE | - | - | N | 6 |  |
| 414 | `UrlCacheGetGlobalLimit` | CACHE2 | - | - | S | 62 |  |
| 415 | `UrlCacheReadEntryStream` | CACHE2 | - | - | S | 75 |  |
| 416 | `UrlCacheReloadSettings` | CACHE2 | - | - | X | 62 |  |
| 417 | `UrlCacheRetrieveEntryFile` | CACHE2 | - | - | S | 62 |  |
| 418 | `UrlCacheRetrieveEntryStream` | CACHE2 | - | - | S | 75 |  |
| 419 | `UrlCacheServer` | STUB | - | - | N | 6 | #112,RegisterUrlCacheNotification |
| 420 | `(ordinal-only) IsLanConnection` | CONN | - | - | E | 64 |  |
| 421 | `(ordinal-only) IsDialUpConnection` | CONN | - | - | E | 66 |  |
| 422 | `(ordinal-only) RegisterForNetworkChangeNotification` | CONN | - | - | E | 64 |  |
| 423 | `(ordinal-only) UnRegisterNetworkChangeNotification` | CONN | - | - | E | 42 |  |
| 424 | `UrlCacheSetGlobalLimit` | CACHE2 | - | - | X | 62 |  |
| 425 | `UrlCacheUpdateEntryExtraData` | CACHE2 | - | - | S | 64 |  |
| 426 | `UrlZonesDetach` | SEC | - | - | I | 126 |  |
| 427 | `_GetFileExtensionFromUrl` | URL | - | - | H | 131 |  |
