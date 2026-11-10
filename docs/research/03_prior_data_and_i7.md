# 03 - Prior Win10 data and Industrial7 state (wininet / sspicli / schannel)

Role: PRIOR DATA AND INDUSTRIAL7 STATE. Everything here is second-hand evidence collected by earlier lanes;
it is a head start and a regression list, not a substitute for running this corpus on the local Win10 VM.
Raw rows are copied (small text files) into `docs/research/data/`; provenance is given per fact.

Oracle for all "Win10" rows below: Windows 10 22H2 (19041.x) qemu guest run by lane G (`laneg`), standard user
and administrator, three boots each, rows byte-identical unless noted. Rows tagged **[W10]** were measured on
genuine Win10. Anything tagged **[ref]** came from Wine/docs and is NOT evidence.

---------------------------------------------------------------------------------------------------------

## A. Earlier lane-G Win10 wininet probes (bb depot)

### A.0 Depot inventory (downloaded to /home/iceisfun/w10lab/depot/)

| depot | file | sha256 | what | records |
|---|---|---|---|---|
| m206 | win10_wininet_probe.exe | 4797d3b1...a37b | task 64: ~128 offline+online rows | m210 `task64-runs.tar.gz` |
| m207 | win10_wininet_date_probe.exe | 2fe37a75...23b2c3 | task 65: 14 date variants x 4 headers x 3 buffer sizes | m212 `task65-runs.tar.gz` |
| m211 | win10_wininet_hdrlen_probe.exe | 86b00928...5a74b | task 67: header-length rules, W/A | m216 `task67-runs.tar.gz` |
| m217 | win10_wininet_hdrlen2_probe.exe | 17819724...56ef971 | task 68: exact-length boundary rows (two-header literal, lengths 18/17/16/15/14/9/8/0/sentinel) | **no result tarball in the depot yet**; bb #1142 reply #16729 says it was booting. Not measured as far as we have data. |
| m64 | task23-sspi-runs.tar.gz (exe m53 `task23-sspi-4ab930ca1f.exe`) | 0f6cabbb...d7 | SSPI / schannel provider probe (not wininet but the TLS plumbing wininet uses) | 82 rows x3 |

Probe SOURCE for m206/m207/m211/m217 is not published anywhere (depot has only the exes, bb thread #1142 has the
narrative). Consequently the flags passed to `InternetOpenW`/`HttpOpenRequestW` in the online rows are not known
exactly (e.g. the `redir.status = 302` row shows the probe did NOT follow the redirect - presumably
`INTERNET_FLAG_NO_AUTO_REDIRECT`; unverified). Treat probe-defect notes below as authoritative. Server for these
probes: a host-side deterministic HTTP server reached through qemu guestfwd `10.0.2.100:8080`; routes `/hello`
(Server: i7probe, text/plain, Last-Modified Tue, 15 Nov 1994 12:45:26 GMT, X-Test "  42", two X-Multi,
Set-Cookie c=1, Content-Length 12), `/notfound` 404 (4-byte body), `/empty` 204, `/redir` 302 -> /hello,
`/big` 20000 bytes, POST echo. Task 64/67 rows are identical in all 6 boots (md5 9b7f9a92... and 291a687c...).
Task 65 differs across boots only where Win10 fills missing date fields from the clock.

Other sources of Win10 wininet-adjacent rows (in the industrial7 repo, `userland/wintests/win10/expected/`):
`win10_wn_n8_probe.win10.txt` (proxy configuration: winhttp mostly, plus `wininet.connected`) and
`win10_wn_n15_probe.win10.txt` (loopback download comparison winhttp / wininet / urlmon). Copied to
`data/i7_wn_n8_proxy_cfg.win10.txt` and `data/i7_wn_n15_wininet_urlmon.win10.txt`.

### A.1 Facts recorded [W10] (task 64: `data/laneg_task64_wininet_probe_std1.txt`)

**InternetOpenW**
- `INTERNET_OPEN_TYPE_DIRECT` ok. `INTERNET_OPEN_TYPE_PROXY` with NULL proxy name = 87. `INTERNET_FLAG_ASYNC` ok.
  NULL agent ok. access type 99 = 87.

**InternetConnectW**
- NULL server = 87. **Empty server "" = 123 (ERROR_INVALID_NAME)**, not 87. Garbage session handle = 6.
  Service type 99 = 87. FTP service to a port with no listener = 12029. HTTP ok (no connect happens until send).

**HttpOpenRequestW**
- called on a session (not a connect) handle = 12018 (ERROR_INTERNET_INCORRECT_HANDLE_TYPE). Garbage connect = 6.
- Defaults ok: `HTTP_QUERY_REQUEST_METHOD` = "GET" (W: 6 bytes), `HTTP_QUERY_VERSION` = "HTTP/1.1" (16 bytes).
  (Request-method query works without the `HTTP_QUERY_FLAG_REQUEST_HEADERS` flag.)

**Before HttpSendRequest** (request handle fresh)
- `HttpQueryInfo(STATUS_CODE)` and `(RAW_HEADERS_CRLF)` return **ok, err 0** (NOT 12019/12150).
- `InternetReadFile` = ok, 0 bytes. `InternetQueryDataAvailable` = ok, avail 0.

**Handle misuse**
- CloseHandle-twice (InternetCloseHandle second call) = 6; garbage handle close = 6. HttpSendRequest on a session
  handle = 12018, on garbage = 6. `InternetReadFile(NULL...)` = 6.

**InternetSetOption / QueryOption**
- `CONNECT_TIMEOUT`(2) set on a session and globally: ok (0 also ok); length 2 = **12010**
  (ERROR_INTERNET_BAD_OPTION_LENGTH). Query returns the set value (12345); short buffer = 122 and needed = 4.
- `USER_AGENT`(41) set on a connect handle = 12018; on the session ok. Query on a connect handle = 12018 (need=2 reported).
- `HANDLE_TYPE`(9) set = 12011 (ERROR_INTERNET_OPTION_NOT_SETTABLE). Query: session = 1 (INTERNET_HANDLE_TYPE_INTERNET),
  connect = 4 (CONNECT_HTTP).
- unknown option 99999 = **12009** (ERROR_INTERNET_INVALID_OPTION).
- `CALLBACK`(1) set on a session = 12011; with a NULL (global) handle = 12018.
- QueryOption with NULL length pointer = 87; garbage handle = 6.

**Response queries (GET /hello 200, /notfound 404, /empty 204, /redir 302 not followed)**
- STATUS_CODE|FLAG_NUMBER: 200/404/204/302, length 4.
- STATUS_TEXT (W): "OK" len 4 bytes (excludes NUL); A flavour len 2. Short (2-byte) buffer: W = 122 need 6 (bytes incl. NUL),
  A = 122 need 3. "Not Found": W 18/need 20, A 9/need 10. "No Content": W 20/need 22, A 10/need 11. "Found": W 10/need 12, A 5/need 6.
- VERSION "HTTP/1.1" len 16. CONTENT_LENGTH|NUMBER: 12 / 4 / 0 / 0.
- RAW_HEADERS_CRLF: the full header block including status line, and a trailing blank line ("...\r\n\r\n");
  lengths 362 (/hello), 142 (404), 92 (204), 118 (302) in bytes. RAW_HEADERS (NUL separated) not probed.
- Custom header `X-Test` sent as "  42": returned "42" (leading blanks trimmed), W len 4. `X-Multi` appears twice: index 0 -> "a",
  then the second query returns "b" and the in/out index is 2 afterwards; missing header = **12150**
  (ERROR_HTTP_HEADER_NOT_FOUND). QUERY_CUSTOM with NULL buffer = 87.
- LAST_MODIFIED|SYSTEMTIME: 16 bytes, y=1994 m=11 d=15 dow=2 h=12 mi=45 s=26; 8-byte buffer = 122 need 16.
  Without the flag: header text unchanged (len 58 bytes for the 29-char date).
- SET_COOKIE returns "c=1" (len 6 bytes). CONTENT_TYPE "text/plain".
- `STATUS_CODE | HTTP_QUERY_FLAG_REQUEST_HEADERS` = **12154** (ERROR_HTTP_INVALID_QUERY_REQUEST). NULL length pointer = 87.

**Body reading**
- QDA before reading = Content-Length (12, 4); zero-length ReadFile ok got 0; read loop gets whole body; read after EOF =
  ok, 0 bytes; QDA after EOF = ok, 0.
- /big (20000): first QDA between 1 and 20000; ONE ReadFile of 30000 bytes returned all 20000.

**POST / headers**
- HttpSendRequestW with header length 0xFFFFFFFF and non-NULL headers: success, server saw the body and Content-Type.
- Header length 8 on a 34-char "Content-Type: ..." string (cuts to "Content-") = **12150**; and the post.send_len8_nobody row.
- Re-sending a request after complete send/read: 12002 (ERROR_INTERNET_TIMEOUT) in the probe sequence (probe-defect: body not
  drained, not a clean test).
- Probe defects (lane G's own): `custom_xtest_number` rows put the name in the wrong buffer (12150 void); two rows glued by a stray \n.

### A.2 Task 65 date handling [W10] (`data/laneg_task65_date_probe_std1.txt`, 226 rows)

Server returns each of 14 variants in Last-Modified, X-Date, Date, Expires. Query flags: text, then `|HTTP_QUERY_FLAG_SYSTEMTIME`
with 16/8/32-byte buffers.

- Win10 is **lenient**: failure code for an unparsable date is **12154** (not 12153). Buffer 8 -> 122 with length 16;
  buffer 16/32 -> ok, length 16. Text query (no flag) always returns the header as sent; an empty header text query is ok len 0.
- Complete RFC 1123 / RFC 850 (`Tuesday, 15-Nov-94 12:45:26 GMT`) / asctime (`Tue Nov 15 12:45:26 1994`) -> 1994-11-15 12:45:26 dow 2.
- Truncated `Tue, 15 Nov` -> ok y=**2000** m=11 d=15 with time of day from the clock.
- `15` (number only) and empty string -> ok, the WHOLE value is the current date/time (guest clock).
- `not a date`, out-of-range `Mon, 32 Feb 2024 25:61:61 GMT` -> 12154.
- No GMT -> ok 12:45:26; date only -> 00:00:00; wrong weekday `Wed, 15 Nov 1994 ...` -> ok dow=3 (name taken, not recomputed);
  2-digit year `94` -> 1994; blank padded -> ok; numeric zone `+0100` -> ok, time unchanged (zone ignored).
- LAST_MODIFIED, DATE and custom X-Date behave identically. **QUERY_EXPIRES|SYSTEMTIME returned 12154 for EVERY variant, even the
  complete RFC date** (text query works). Unexplained; possibly a probe issue with the constant. Re-measure.
- Rows differing per boot = the clock-filled ones (v03 time of day, v05/v06 whole value); do not hard-CHECK those fields.

### A.3 Task 67 header-length rules [W10] (`data/laneg_task67_hdrlen_probe_std1.txt`, 22 rows, all 6 boots identical)

Server echoes X-T / X-A request headers.

W (HttpSendRequestW) with `L"X-T: 1\r\n"` (8 WCHARs):
- length 0xFFFFFFFF ok, X-T=1 sent (earlier claim "W sentinel = 87" did NOT reproduce).
- explicit 8 ok. **16 (bytes) = 12150** (no request sent). 9 = 12150 (reads past NUL). 7 = ok X-T=1. 0 with non-NULL = ok X-T=1
  (0 means NUL-terminated for W).
- two headers `X-T: 1\r\nX-A: 2\r\n`: sentinel ok both; length 17 (one past content) = 12150; explicit 8 = only X-T.
- NULL headers with length -1 or 8 = ok, no header sent.

A (HttpSendRequestA): sentinel ok (both headers); 8 ok; **length 0 with non-NULL headers = 87** (differs from W).

HttpAddRequestHeadersW with sentinel / len 8, and A with sentinel: all ok and header sent (A sentinel test used the one-header form only).

Task 68 (m217) would fix the remaining boundary rows (exact 16, 15, 14, 18); no data yet -> **unmeasured**.

### A.4 Task 23 SSPI record [W10] (`data/laneg_task23_sspi_{std,adm}.txt`, 81 rows; std and adm differ only in `env.token elevated`)

- `InitSecurityInterfaceW` table version 1, all of enum/qpi/ach/fch/isc/dsc/fcb/qca present.
- `EnumerateSecurityPackagesW` returns **12** packages in this order: Negotiate, NegoExtender, Kerberos, NTLM, TSSSP, pku2u, CloudAP,
  WDigest, Schannel, "Microsoft Unified Security Protocol Provider", "Default TLS SSP", CREDSSP. Caps/maxtoken recorded:
  Schannel caps 0x004107b3 rpcid 14 maxtoken 24576 (same for the Unified and Default TLS names); NTLM 0x02882b37 maxtoken 2888;
  Negotiate 0x00883bb3 48256; Kerberos 0x028f3bbf 48000; CREDSSP 0x00810733 rpcid 65535 maxtoken 73032.
- `AcquireCredentialsHandleW` on Schannel / Unified with SCHANNEL_CRED v4 and v5 (and NULL auth data) -> 0 (SEC_E_OK) for outbound.
  NTLM/Negotiate in/out ok.
- `InitializeSecurityContextW` first call (Schannel, target localhost or an invalid name, req 0x811c): returns **0x00090312
  (SEC_I_CONTINUE_NEEDED)**, attrs 0x811c, one output buffer type 2 (SECBUFFER_TOKEN) of 128-255 bytes (a ClientHello); the target name
  is not validated at that point. Delete/free ok.
- Module state: schannel, sspicli, bcrypt loaded after EnumerateSecurityPackages; ncrypt not loaded until later (ncrypt.dll `pre=0`);
  `ncryptsslp` not loaded. Registry: `HKLM\...\SecurityProviders` = "credssp.dll"; `Lsa\Security Packages` multi_sz of one empty-ish
  entry; SCHANNEL key opens but `Protocols` key has no children.
- Exports of schannel.dll, sspicli.dll, secur32.dll all include AcquireCredentialsHandleW, InitSecurityInterfaceW,
  InitializeSecurityContextW, EnumerateSecurityPackagesW; schannel also SpLsaModeInitialize/SpUserModeInitialize.

### A.5 Other Win10 wininet-adjacent rows recorded by the industrial7 tree [W10]

`win10_wn_n15_probe` (loopback server in-process, extracted wininet/urlmon portion in `data/i7_wn_n15_wininet_urlmon.win10.txt`):
- `InternetOpenUrlW` + `HttpQueryInfoW` + `InternetReadFile` for six paths: Content-Length 10; chunked (3 chunks, total 13, no
  Content-Length header -> 12150, Transfer-Encoding "chunked"); close-delimited (total 17); 206 with `Content-Range: bytes 2-5/10`
  (total 4); HEAD via `HttpOpenRequest`/`HttpSendRequest` (status 200, Content-Length 10, body 0); 301/302 followed by default
  (final response 200, server saw `GET /len10` second); 302 with `INTERNET_FLAG_NO_AUTO_REDIRECT` -> status 302, Location
  http://127.0.0.1:PORT/len10, body 5; 404 (body 9 bytes readable, status 404 - InternetOpenUrl does NOT fail on 404);
  truncated body (Content-Length 100, 40 sent) -> total 40, read terminates as EOF, no error recorded in the terminator.
- urlmon `URLDownloadToFileW`: HRESULT 0 with size 10/13/17/10(302)/40(trunc); **404 -> 0x800C0006 (INET_E_OBJECT_NOT_FOUND)**, size 0.
- `win10_wn_n8_probe` (`data/i7_wn_n8_proxy_cfg.win10.txt`), wininet part: `InternetOpenW(DEFAULT/PRECONFIG/NO_PROXY/automatic/NAMED)`
  query options (`INTERNET_OPTION_PROXY` access=1 for default/noproxy/automatic, access=3 + `np:3128` + bypass `<local>` for named; size query
  122 with need nonzero), and `InternetGetConnectedState` is callable. Most of the file is winhttp proxy-config (WinHttpGetIEProxyConfig,
  WinHttpGetDefaultProxyConfiguration, WinHttpGetProxyForUrl: PAC garbage 12166, flags 0 = 87, empty url 12006, NULL session 6).

---------------------------------------------------------------------------------------------------------

## B. What Industrial7 implements today (read from /home/iceisfun/work/industrial7)

| component | state | where |
|---|---|---|
| **wininet.dll** | stock Win7 wininet is used in default layouts (`OWNED_STATUS.md`: wininet "stock-only", unowned). A **Win10 personality image `wininet-w10`** exists (host-built, not booted/staged by default, bb #871, `lanee/871-wininet`): exports exactly the 327 Win10 22H2 slots (299 named + 28 ordinal-only, ordinals 101-427) from `data/wininet.def`. **Real logic only for 10 exports**: `InternetCrackUrlA/W` (14-argument form incl. `f_keep_zone_identifier`), `InternetCanonicalizeUrlA/W` (4-arg, 87 for NULL/zero length, 122 too small), `InternetTimeFromSystemTime{,A,W}`, `InternetTimeToSystemTime{,A,W}`. The other 317 return `ERROR_INTERNET_CANNOT_CONNECT` 12029 (44 network functions) or `ERROR_CALL_NOT_SUPPORTED` 120 (rest). A later branch `lanea/wininet-dataplane` adds a host-only data-plane core (handles, request state) with every rule labelled `[V-ref]` (Wine) or `[unverified]`; per its own text there was "no Win10 oracle row for any data-plane behaviour". Lane G's probes A.1-A.3 above were commissioned from that list. | `docs/design/win10/WININET-W10-LINK.md`, `crates/w10-wininet-core`, `userland/guest/wininet-w10` |
| **wininet transport** | none in the image. Proposed: wrap `w10-winhttp-core` (handle table, exchange, redirect, pool, secflags) and share a guest `plat/`; includes an **error map** WinHTTP 12175 + flag mask -> WinINet codes: INVALID_CA 0x8->12045, CN_INVALID 0x10->12038, DATE_INVALID 0x20->12037, REVOKED 0x4->12170, REV_FAILED 0x1->12057, WRONG_USAGE 0x40->12055, INVALID_CERT 0x2->12169, SECURITY_CHANNEL_ERROR ->12157; 12175 never reaches a WinINet caller. All pinned by host tests only (`winhttp_contract.rs`). | WININET-W10-LINK.md section 6 |
| **Stock wininet on Win7 i7 guests** | reaches socket creation, sets `SIO_SET_COMPATIBILITY_MODE`, closes without connect; `HttpSendRequest` fails 12029; `nlaapi` RPC (NLA) is missing; "WinINet does not reach TLS" (`docs/TLS.md` 7.1, `design/i7update/RESEARCH.md`). No wininet gate in smoke; `test_wininet_https` exists but is not in a gate. | `docs/TLS.md`, `docs/stage4/INVENTORY.md` |
| **URL measurement corpus** | 288 cases x surfaces (ntdll literal parsers, IDN, shlwapi, **wininet InternetCrackUrl/Canonicalize**, winhttp, urlmon) recorded as JSON; on i7 the wininet surface produced **0 records (loader fault)**; "Native Win7 reference execution remains outstanding". So there is no Win10 crack/canonicalize ground truth from this corpus either. | `docs/URL_CORPUS.md`, `userland/wintests/url/adapt_wininet.h` |
| **sspicli.dll** | **owned-default shim** (replaces stock; forwards 59 exports to `sspicli7.dll`; owner lanea crypto bb#545/#535). A Win10 `sspicli-w10`/`secur32-w10` image exists: sspicli 105 exports (ordinals 1..105), secur32 101 (91 forwarders `SSPICLI.<name>`, 10 bodies at ordinals 1,2,3,27,28,74,75,76,98,99). `crates/w10-sspicli-core` holds dispatch logic of 34 exports; labelled [V-corpus]/[L]/[U]; the lsa/NTLM identity side (cryptbase) is "not reconciled", **Win10 oracle needed**. | `docs/design/win10/SSPICLI-W10-LINK.md`, `SSPICLI-OVERLAP.md`, `SSPICLI-CRYPTBASE.md` |
| **schannel.dll** | `schannel-w10`: 36 corpus exports (24 forwarders to SSPICLI, `SpLsaModeInitialize`, `SpUserModeInitialize`, ten `Ssl*` helpers); built, host-tested, one guest probe; not staged. TLS engine `i7tls` (Rust, TLS 1.2/1.3, 5/44 byte STREAM_SIZES for 1.3 etc.) sits behind the SSPI table; interim owned `schannel.dll`/`security.dll` on C:. Doc admits "Win10 22H2 lists no TLS 1.3 / ChaCha20" from the corpus but the real list lives in ncrypt/CNG, i.e. **unverified**: default suite order, SCH_CREDENTIALS v5 protocol enablement. | `SCHANNEL-W10-LINK.md`, `SCHANNEL-CONFORMANCE.md`, `TLS.md`, `TLS-W10-PLAN.md` |
| **winhttp.dll** | `w10-winhttp-core` pure core (URL, headers, dates, timeouts, proxy config, handle table); `winhttp-w10` guest image runs in hybrid probes (`userland/wintests/w10winhttp`, `expected.tsv` with [V-corpus]/[rfc]/[L]/[observed]/[unverified] tags - most are regression pins, not Win10 truth). Genuine winhttp works on the GUI-apps C: with the Win7 ws2_32 (`smoke-winhttp` PASS). | `WINHTTP-CORE.md`, `WINHTTP-W10-LINK.md`, `TLS.md` 6 |
| **urlmon** | Win7 crate with three real exports (IsValidURL, CoInternetParseUrl, CreateUri) plus honest-failure stubs; a separate `urlmon-w10` slice. | `URLMON-OWNED.md`, `URLMON-W10-LINK.md` |
| **TLS testing** | `w10sspi` (handshake, ALPN, mTLS, neg, hostile) and `w10schannel` loopback programs, `w10curl` contract; TLS in guest E2E against a fixture; curl (Schannel backend) uses SSPI directly, not wininet. | `userland/wintests/w10*`, `TLS-W10-GUEST-E2E.md` |

### B.1 Consumers: who calls which wininet / sspicli APIs

- **Notepad++ (npp)**: dies at `LDRFAIL WININET.dll` (stock not in the family payload; KB-TOOLDIRS). Motivation for `wininet-w10`: the module must
  load export-complete; its plugin updater (URL crack for update URLs, then `InternetOpen`/`InternetOpenUrl`/`HttpOpenRequest`...) should fail gracefully.
  Also `wininet_url` test in NOTEPAD_BRINGUP crashed with 0xc0000409 on stock earlier.
- **Chrome 109 (`chrome.dll`, `mf.dll`)**: delay-imports wininet (`chrome_closure.tsv`: "image delay 18" = imported by 2 modules);
  the only named symbol in `chrome_imports.tsv` is `GetUrlCacheEntryInfoExW` (count 1) - cache query for proxy/IE settings. Whether Chrome needs more than that import is not established in the tree.
- **Git (for Windows)**: imports ~10-11 wininet symbols (SELFHOST-USERLAND-GAPS*: "wininet (git 10)"), as a no-DLL image gap. Git/cargo's libcurl use the
  Schannel SSPI table (ISC/QCA attribute checklist `test_w10_curl_contract`), not wininet.
- **Firefox**: FFX-BLOCKERS lists wininet with 2 importing images, 327 exports, 10 implemented.
- **TLS stack**: wininet `HttpSendRequest` over https needs SSPI `SealMessage/UnsealMessage`, `CertFindChainInStore`,
  `CertSelectCertificateChains` (TLS-W10-PLAN); loads schannel via `LoadLibrary("schannel")` + `InitSecurityInterfaceA`.
  Needs nlaapi RPC (network location awareness) and (stock) 20+ delay-loaded DLLs.
- **i7update (Rust)** deliberately avoids WinINet (RESEARCH.md: "Avoid it"; WinINet does not reach TLS).
- **sspicli consumers**: schannel (24 forwarders into sspicli), secur32 (91 forwarders), winhttp/webio, wininet (via `InitSecurityInterface`),
  curl, CredSSP/TSSSP, advapi32 LSA calls, and every Win10 binary that links secur32.

---------------------------------------------------------------------------------------------------------

## C. Measured vs not measured on Win10 (for planning this corpus)

### C.1 Measured [W10] (good seeds for hard CHECKs; re-verify in our own tests)

Error-code ladder for handle misuse (6 / 12018 / 87 / 123), option set/query errors (12010 / 12011 / 12009 / 12018 / 122 + need=4),
default request method/version, pre-send query/read/QDA success with empty answers, A/W sizing for STATUS_TEXT, RAW_HEADERS_CRLF shape,
custom-header trim/index semantics and 12150, SYSTEMTIME query rules including lenient parsing and clock fill (12154 on failure),
header-length rules for HttpSendRequest W/A and HttpAddRequestHeaders, response body semantics for Content-Length / chunked / close-delimited /
206 / HEAD / 204 / 404 / truncated, auto-redirect default vs NO_AUTO_REDIRECT, URLDownloadToFile HRESULTs, SSPI package list and the first
Schannel ISC token result, proxy option query shapes for InternetOpen.

### C.2 NOT measured on Win10 (open work)

1. **Wire-level request shape**: no row records what the client SENT (request line, header order/casing, default `Accept`, `User-Agent`,
   `Host`, `Connection`, `Accept-Encoding`, `Content-Length` for POST, chunked uploads, Cookie, Authorization, `Referer`). Only echoed X-T/X-A.
2. **HTTPS** through wininet (cert errors 12037/12038/12045/12157/12175, `INTERNET_OPTION_SECURITY_*`, `SECURITY_FLAG_IGNORE_*`, retry via
   `InternetErrorDlg` flags/`ERROR_INTERNET_INVALID_CA` flow, SECURITY_CERTIFICATE_STRUCT, certificate context option), TLS version options.
3. **Cookies** (`InternetSetCookieEx/GetCookieEx`, HttpOnly, domain/path matching, `INTERNET_COOKIE_THIRD_PARTY`, `InternetSetCookie` return codes),
   **URL cache** (CreateUrlCacheEntry/Commit/Retrieve/Unlock/FindFirst/Next/Delete, `INTERNET_CACHE_ENTRY_INFO` layout, cache option flags,
   `GetUrlCacheEntryInfoEx`), **offline mode**, `INTERNET_FLAG_RELOAD/NO_CACHE_WRITE/RESYNCHRONIZE`.
4. **Authentication** (401/407, Basic/Digest/NTLM, `INTERNET_OPTION_USERNAME/PASSWORD`, `HttpSendRequestEx`, `InternetErrorDlg` no-UI).
5. **Proxy**: connection through a proxy, `INTERNET_OPTION_PROXY*`, per-connection settings and bypass (only the query shapes of A.5).
6. **FTP** (`FtpOpenFile`, `FtpFindFirstFile`, `FtpGetFile`, `FtpCommand`, PASV/active, 12xxx codes) and Gopher (removed).
7. **Async mode** (`INTERNET_FLAG_ASYNC` is only measured as an open succeeding): status callbacks sequence, `ERROR_IO_PENDING`,
   `INTERNET_STATUS_*` ordering, `HttpSendRequestEx/EndRequest`, `InternetWriteFile`, handle-closing callbacks, `InternetSetStatusCallback` return values.
8. **`InternetCrackUrl` / `InternetCanonicalizeUrl` / `InternetCreateUrl` / `InternetCombineUrl` / `InternetTimeToSystemTime`/`FromSystemTime`**:
   no Win10 reference rows exist in the industrial7 tree (the URL corpus on Win7/i7 produced 0 wininet records; Win10 run outstanding).
   Industrial7 values come from Wine/shlwapi tables and the decompilation, i.e. [ref].
9. **Keep-alive/connection pooling, max connections per server (`INTERNET_OPTION_MAX_CONNS_PER_SERVER`), timeouts** (send/receive timeouts,
   12002 behaviour), `InternetSetOption` families beyond connect timeout and user agent, `InternetQueryOption` general set
   (`INTERNET_OPTION_REQUEST_FLAGS`, `URL`, `HTTP_VERSION`, `DATAFILE_NAME`, `CONNECTED_STATE`, `INTERNET_OPTION_SETTINGS_CHANGED`, ...).
10. **Content decoding** (`INTERNET_OPTION_HTTP_DECODING`, gzip), **Expect: 100-continue**, HTTP/1.0 servers, malformed responses, folded headers,
    multiple status lines, oversize headers (12152/12150), early close (12031 12030), `HttpQueryInfo` for every `HTTP_QUERY_*` index
    (only status code/text/version/content-length/content-type/raw-headers/last-modified/set-cookie/custom measured).
11. **`HTTP_QUERY_EXPIRES|FLAG_SYSTEMTIME` = 12154 always** is unexplained; **task 68 exact-length boundary rows** produced no data; **re-send 12002**
    only anecdotal.
12. `InternetGetConnectedState(Ex)`, `InternetCheckConnection`, `InternetAttemptConnect`, `InternetGoOnline`, `InternetAutodial*` (dial-up),
    `InternetConfirmZoneCrossing`, `InternetSetPerSiteCookieDecision`, `InternetQueryFortezza...` and the COM / ordinal-only slots
    (28 unnamed ordinal exports have no behavior information at all).
13. sspicli beyond the first ISC call: full handshake against a wininet-like server, `QueryContextAttributes` set (STREAM_SIZES, CONNECTION_INFO,
    ALPN, REMOTE_CERT), `SealMessage/UnsealMessage`, `DeleteSecurityContext`, error STATUS for bad parameters, credential reuse; most of that is in
    industrial7's own `w10sspi` tests tagged [observed], not Win10-measured.
14. urlmon/winhttp/crypt32/ws2_32 conformance: only `URLDownloadToFileW` HRESULTs and winhttp proxy / loopback download rows exist.

### C.3 Suggested use for this corpus

Seed hard CHECKs from C.1 (after re-verifying on the VM with our in-process loopback server and the connection recorder); fill C.2 items 1, 3, 7,
8, 9, 10 first because they define wininet's observable behaviour and have no Win10 data; keep `t_note` for the clock-dependent date fields and
for anything depending on probe flags that were not recorded (see A.0).

Raw data index: `docs/research/data/` (`laneg_task64_*`, `laneg_task65_*`, `laneg_task67_*`, `laneg_task23_sspi_*`, `i7_wn_n8_*`, `i7_wn_n15_*`).
