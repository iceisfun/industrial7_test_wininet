# gopher_and_stubs: evidence

The area prefix is `gs_`. The source files are:

| File | What it covers |
|---|---|
| `gs.h`, `gs_util.c` | Prototypes, ordinal typedefs and helpers |
| `gs_gopher.c` | Gopher and the shared ERROR_CALL_NOT_IMPLEMENTED stub, plus gopher in the URL and connect layers |
| `gs_stubs.c` | Named and ordinal stubs with constant behaviour, Fortezza, DAV, P3P, cache-server ordinals, cookie-file ordinals and COM entry points |
| `gs_dial.c` | Autodial, dial, hang-up, go-online, dial state and connected state; ordinals #101 and #420-#423 |
| `gs_misc.c` | Privacy zone preferences, HSTS, HTTP push, dependency handles, security info by URL, cache-entry unlock edges, request-file locks, cache-group attributes and cache header counters |
| `gs_appcache.c` | AppCache validation, HttpGetServerCredentials, HttpGetTunnelSocket, UpdateUrlCacheContentPath(NULL), UrlZonesDetach and Passport resolve-only checks |
| `gs_ordinals2.c` | #103 PerformOperationOverUrlCacheA, #403, ordinal-only address map and the #112 folded names |
| `gs_websocket.c` | HttpWebSocket* argument and handle validation |
| `gs_exports.c` + generated `gs_exptab.c` | Every export of wininet, urlmon, winhttp, sspicli, schannel, crypt32 and ws2_32 resolves by name and ordinal, name and ordinal agree, and forwarders land in their targets |

`gen_exptab.py` builds `gs_exptab.c` from `tools/<module>_exports.json`.

**Oracle and decomp.** The oracle is the Windows 10 22H2 VM (10.0.19045, wininet 11.0.19041.2193), run through `tools/vm_run.sh`. Boots: `gsb2` crashed (literal URL into ShowSecurityInfoByURLA), `gsb3` had 9 FAILs, `gsb4` had 1 FAIL (#103 return), and `gsb5` passed all 195 tests. The decomp comes from the Win10 reference corpus (`/api/function/wininet/<name>/decomp`).

**Tags in the source.** `[D fn@rva]` means the expectation was read from the decomp. `[VM]` / `[VM boot N]` means it was observed on the guest because the decomp was silent or wrong about it. `[K]` means general WinINet knowledge. Every hard CHECK has passed on the VM. Anything that varies between machines (RAS phonebook, preload list, privacy templates, group list contents) is a `t_note`.

**Network and state.** No test uses the network. The only server is the in-process loopback HTTP server in `gs_lock_request_file_after_download`. Cache entries and groups use `t_uniq_*` names and are deleted. Privacy Set is called only with arguments that fail validation; the original template is written back if one unexpectedly succeeds. These are never called:
- AppCache create/delete-with-a-real-URL/free-space
- UpdateUrlCacheContentPath with a path
- IncrementUrlCacheHeaderData with a valid index
- InternetSetSecureLegacyServersAppCompat
- the Passport/nexus calls
- DllRegisterServer
- the UI functions ShowSecurityInfo, ShowX509EncodedCertificate and InternetErrorDlg

## Decomp-grounded (and VM-confirmed)
| Behaviour | Source |
|---|---|
| Gopher*A/W, InternetWriteFileExA/W and LoadUrlCacheContent are one body: `SetLastError(120); return 0`. No argument is read and no output is written, for any handle or thread. On the VM all 13 names share one address. | GopherCreateLocatorA@0x138810 |
| InternetConnectA/W accept only service 1 (FTP) and 3 (HTTP), checked by `(svc-1) & ~2`. Anything else, including GOPHER=2, fails with 87 before the handle is looked at, even with a NULL session. | InternetConnectA@0x138070 |
| ShowCertificate, ShowClientAuthCerts and ParseX509EncodedCertificateForListBoxEntry: `SetLastError(120); return 120` (a DWORD). | @0x1847f0 |
| DeleteIE3Cache returns 120 without touching GLE. RunOnceUrlCache, DllInstall and InternetGetCertByURL(A) return 0 without touching GLE. UrlCacheServer, RegisterUrlCacheNotification and #112 return 1. DispatchAPICall is a bare `ret`. | @0x1a7320, @0xdabf0, @0xdb0e0, @0xdac00 |
| InternetFortezzaCommand and InternetQueryFortezzaStatus: GLE 120, FALSE, status untouched. | @0x14a060 / @0x14a0d0 |
| HttpCheckDavCompliance (= #104) and #105: `*out = 0` when out is non-NULL. GLE is 87 when url, token or out is NULL or reserved is non-NULL, otherwise 12016. Always FALSE. There is no named W export. | @0x167230 / @0x1672f0 |
| #120-#123 GetP3PPolicy: GLE 120, returns 0xFF. #346: returns 0x103. #401: returns 0. #402: zeroes 0x28 bytes of arg2 and returns 0. #410: `*p = NULL`, returns E_FAIL. #411: returns E_INVALIDARG or E_FAIL by arg1. #413: returns E_FAIL. | ordinal bodies |
| #118 FindP3PPolicySymbol: NULL gives -1. Only 3- and 4-character exact (case-sensitive) tokens match. The bare token equals the `a` form. | @0x167210 |
| #102 GetDiskInfoA: a path that is NULL, shorter than 2 characters or 260 characters or longer fails with 87. Otherwise it calls GetDiskFreeSpaceExA and sets `*pdw = 1`. | @0x1a7330 |
| #103 PerformOperationOverUrlCacheA: a FindFirst failure returns FALSE (also for ERROR_NO_MORE_ITEMS on an empty group). The loop path returns `GLE == 259`, but GLE is read **after** FindCloseUrlCache, which resets it to 0, so a complete walk returns FALSE with GLE 0 (VM boot 4). The callback sees every group entry and gets the context. | @0x1a7420 |
| #403: arg2 NULL, `arg2[0] == 0`, `arg2[1] == 0` or arg3 NULL gives E_INVALIDARG, returned as an HRESULT before any initialisation. | @0x165fc0 |
| #116/#117 IsDomainLegalCookieDomain: NULL gives 87. Otherwise a reversed-domain match (the parent domain matches, a sibling or partial label does not). | @0x1ea30 |
| InternetAutodial: `flags & ~0xF` gives 87; valid flags are a no-op that returns TRUE with GLE 0. InternetAutodialHangup: reserved gives 87. InternetDial(A/W) returns a DWORD, sets `*conn = 0` first and never sets GLE. InternetHangUp: reserved gives 87. InternetGoOnline: `flags & ~3` gives 87. InternetSetDialState(A/W): always 120. | @0x13c520.. |
| InternetGetConnectedState(Ex) with reserved non-zero gives FALSE, 87 (`*flags` is cleared first). | InternetGetConnectedStateExW@0xd8340 |
| PrivacyGetZonePreferenceW: zone in [5,999] or above 10000, or type > 1, gives 87. A NULL buffer with a non-zero length, or a buffer with a NULL length, succeeds early. `*len <= strlen` gives 234. PrivacySetZonePreferenceW validation (zone/type/template/pref combination) gives 87. | @0x69630, @0xcea10 |
| HttpIsHostHstsEnabled: `*pf = 0` first. A NULL host or out gives 87. | @0xbc1a0 |
| HttpPushEnable/Wait/Close and HttpOpen/Duplicate/CloseDependencyHandle, HttpIndicatePageLoadComplete: NULL and handle-type validation. A second dependency open on the same request gives 12019. | *Internal helpers |
| InternetShowSecurityInfoByURL(A): only an https URL whose host is in the process SSL cache reaches the dialog. The A entry point **writes a NUL into the caller's URL** while it looks the host up, then restores it. A string literal faults (0xc0000005, boot 2), so the tests pass writable copies. | FindCertEntryInCache |
| UnlockUrlCacheEntryFile(A/W): NULL url or reserved != 0 gives 87. An unknown URL gives 2. The plain name is the A entry point. | @0x1a30d0 |
| InternetLockRequestFile: a NULL, session or connect handle gives 6. An unsent request (no data file) gives 2. Locks are refcounted per handle. InternetUnlockRequestFile with a bad signature gives 87. | @0x1be40 / @0xb790 |
| GetUrlCacheGroupAttributeA: NULL info or len, or reserved, gives 87. `*len < 156` gives 122 and `*len = 156`, before the group lookup. dwGroupSize is never written. Unknown group gives 2. | @0x1a1080 |
| SetUrlCacheGroupAttributeA converts szGroupName **only when bit 0x8 (QUOTA) is set**. GROUPNAME (0x10) alone does not store a name. | @0x1a2b80 (also see urlcache_enum_groups/groups.c) |
| IncrementUrlCacheHeaderData / GetUrlCacheHeaderData: index >= 32 (or NULL out for Get) gives 87. | @0x20960 / @0x295a0 |
| AppCache*: GlobalDataInitialize runs first, then each pointer is checked in order. NULL gives E_INVALIDARG, returned as Win32 87, with outs untouched and GLE untouched. AppCacheLookup: `flags & ~1` gives 87. AppCacheCheckManifest does not validate the master URL. FreeAppCacheGroupList zeroes both fields. AppCacheFreeDownloadList leaves a list with a NULL entry pointer alone. | AppCache*Internal |
| HttpGetServerCredentials: url, user out or password out NULL gives 87 with outs untouched. Otherwise the outs are set to NULL, and an empty password cache gives ERROR_NOT_FOUND (1168). | HttpGetServerCredentialsInternal@0x21d30 |
| HttpGetTunnelSocket: outs are initialised first (`~0`, NULL, 0). NULL handle gives 6. A session or connect handle gives 12018. An unsent request gives 12019. | InternalHttpGetTunnelSocket@0x148f0c |
| UpdateUrlCacheContentPath(NULL): FALSE, GLE 87. | @0x1a3360 |
| UrlZonesDetach: void; zone users keep working afterwards. | @0x17f6c0 |
| HttpWebSocketSend/Receive/Close/Shutdown/QueryCloseStatus: buffer/length consistency, close status >= 1000 and reason < 124 bytes are checked **before** the handle. Then NULL gives 6, and a non-web-socket handle gives 12018 (HANDLE_OBJECT::IsValid tag mismatch). The wrappers always `SetLastError(r)`. CompleteUpgrade on a request without a 101 gives 12019. | InternalWebSocket* |
| Export table: wininet ordinals run 101..427 with no gaps. There are 28 ordinal-only entries with 25 distinct addresses (#104 = HttpCheckDavCompliance, #112 = UrlCacheServer, #120..#123 folded). wininet has no forwarders. Every name and ordinal of the 7 modules resolves and agrees, and the crypt32 → dpapi and schannel → sspicli forwarders land in their targets (1356 rows). | tools/*_exports.json |

## VM-observed (the decomp did not settle it)
- GetProcAddress with an ordinal outside the table fails with **182** (ERROR_INVALID_ORDINAL). With an unknown name it fails with 127.
- `gopher://` URLs: InternetCrackUrl does not default the port, so nPort stays 0 when the URL has none. InternetCreateUrl prints `:70` explicitly. InternetOpenUrl gives 12006 (UNRECOGNIZED_SCHEME).
- HttpIsHostHstsEnabled: `"::1"` (unbracketed) gives 12005 and `""` gives 87, with `*pf` still cleared. On this image the preload list has accounts.google.com, paypal.com, www.paypal.com and twitter.com; this is recorded as a note only.
- HttpGetServerCredentials resets GLE to 0 on the miss path. Unparseable or non-HTTP URLs give 12006, and https gives 1168. Both outs are cleared.
- AppCacheGetGroupList/GetIEGroupList on a fresh profile: 0 groups, but the array pointer is non-NULL. AppCacheFreeGroupList clears it.
- #101 DoConnectoidsExist on the image: FALSE with GLE 3 (left behind by RAS). #420/#421: LAN 1, dial-up 0. InternetGetConnectedState: flags 0x12 ("LAN Connection"). These are notes only.
- SetUrlCacheEntryGroupA(ADD) into a new group with quota 0 gives 1816. The #103 fixture first sets a 1 MB quota on its private group.
- InternetShowSecurityInfoByURLW leaves GLE 0. The A form leaves the seed. Both are notes.
- INTERNET_OPTION_UPGRADE_TO_WEB_SOCKET (103) set on an unsent request: 87 (note).

## Knowledge-only
- The GOPHER_TYPE_* / GOPHER_*_ATTRIBUTE constants used as table inputs (from the SDK). The expectation itself does not depend on them, because the stub reads no argument.
- The InternetGetConnectedState flag bits are only range-checked (`& ~0xFF`).
