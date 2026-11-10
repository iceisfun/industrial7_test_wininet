/* Shared declarations for the gopher_and_stubs area: legacy/removed wininet APIs, fixed-behaviour stubs,
 * dial/online family, ordinal-only exports, small undocumented helpers, and the export-table checks.
 *
 * Evidence tags in comments: [D fn@rva] = Win10 19041 wininet decomp (corpus explorer, file version
 * 11.0.19041.2193), [VM] = observed on the Win10 22H2 guest, [K] = documented / well-known behaviour.
 * See EVIDENCE.md. */
#ifndef GS_H
#define GS_H
#include "t.h"
#include <wincrypt.h>
#include <wininet.h>
#include <stdlib.h>

/* ---- prototypes for exports that mingw does not declare (or declares differently) -------------------- */
UDECL(BOOL,  InternetWriteFileExA, (HINTERNET, LPINTERNET_BUFFERSA, DWORD, DWORD_PTR));
UDECL(BOOL,  InternetWriteFileExW, (HINTERNET, LPINTERNET_BUFFERSW, DWORD, DWORD_PTR));
UDECL(BOOL,  LoadUrlCacheContent, (void));
UDECL(DWORD, ShowCertificate, (HWND, LPVOID));
UDECL(DWORD, ShowClientAuthCerts, (HWND));
UDECL(DWORD, ParseX509EncodedCertificateForListBoxEntry, (LPBYTE, DWORD, LPSTR, LPDWORD));
UDECL(DWORD, DeleteIE3Cache, (HWND, HINSTANCE, LPSTR, int));
UDECL(DWORD, RunOnceUrlCache, (HWND, HINSTANCE, LPSTR, int));
UDECL(BOOL,  InternetGetCertByURL,  (LPSTR, LPSTR, DWORD));
UDECL(BOOL,  InternetGetCertByURLA, (LPSTR, LPSTR, DWORD));
UDECL(DWORD, UrlCacheServer, (void));
UDECL(DWORD, RegisterUrlCacheNotification, (HWND, UINT, GROUPID, DWORD, DWORD));
UDECL(void,  DispatchAPICall, (void));
UDECL(HRESULT, DllInstall, (BOOL, PCWSTR));
UDECL(HRESULT, DllCanUnloadNow, (void));
UDECL(HRESULT, DllGetClassObject, (REFCLSID, REFIID, LPVOID *));
UDECL(BOOL,  InternetFortezzaCommand, (DWORD, HWND, DWORD_PTR));
UDECL(BOOL,  InternetQueryFortezzaStatus, (DWORD *, DWORD_PTR));
UDECL(void,  InternetAutodialCallback, (DWORD, LPCVOID));
UDECL(BOOL,  InternetGoOnline,  (LPSTR, HWND, DWORD));
UDECL(BOOL,  InternetGoOnlineA, (LPSTR, HWND, DWORD));
UDECL(BOOL,  InternetGoOnlineW, (LPWSTR, HWND, DWORD));
UDECL(BOOL,  InternetSetDialState,  (LPCSTR, DWORD, DWORD));
UDECL(BOOL,  InternetSetDialStateA, (LPCSTR, DWORD, DWORD));
UDECL(BOOL,  InternetSetDialStateW, (LPCWSTR, DWORD, DWORD));
UDECL(DWORD, InternetDial,  (HWND, LPSTR, DWORD, DWORD_PTR *, DWORD));
UDECL(DWORD, InternetDialA, (HWND, LPSTR, DWORD, DWORD_PTR *, DWORD));
UDECL(DWORD, InternetDialW, (HWND, LPWSTR, DWORD, DWORD_PTR *, DWORD));
UDECL(DWORD, InternetHangUp, (DWORD_PTR, DWORD));
UDECL(BOOL,  InternetAutodial, (DWORD, HWND));
UDECL(BOOL,  InternetAutodialHangup, (DWORD));
UDECL(BOOL,  HttpCheckDavCompliance, (LPCSTR, LPCSTR, LPBOOL, HWND, LPVOID));
UDECL(BOOL,  HttpCheckDavComplianceW, (LPCWSTR, LPCWSTR, LPBOOL, HWND, LPVOID));
UDECL(DWORD, HttpIsHostHstsEnabled, (LPCWSTR, BOOL *));
UDECL(BOOL,  InternetShowSecurityInfoByURL,  (LPSTR, HWND));
UDECL(BOOL,  InternetShowSecurityInfoByURLA, (LPSTR, HWND));
UDECL(BOOL,  InternetShowSecurityInfoByURLW, (LPCWSTR, HWND));
UDECL(BOOL,  ShowSecurityInfo, (HWND, LPVOID));
UDECL(void,  ShowX509EncodedCertificate, (HWND, PCCERT_CONTEXT));
UDECL(DWORD, PrivacyGetZonePreferenceW, (DWORD, DWORD, LPDWORD, LPWSTR, LPDWORD));
UDECL(DWORD, PrivacySetZonePreferenceW, (DWORD, DWORD, DWORD, LPCWSTR));
UDECL(BOOL,  UnlockUrlCacheEntryFile,  (LPCSTR, DWORD));
UDECL(BOOL,  UnlockUrlCacheEntryFileA, (LPCSTR, DWORD));
UDECL(BOOL,  UnlockUrlCacheEntryFileW, (LPCWSTR, DWORD));
UDECL(BOOL,  InternetLockRequestFile, (HINTERNET, HANDLE *));
UDECL(BOOL,  InternetUnlockRequestFile, (HANDLE));
UDECL(BOOL,  IncrementUrlCacheHeaderData, (DWORD, DWORD *));
UDECL(BOOL,  GetUrlCacheHeaderData, (DWORD, DWORD *));
UDECL(BOOL,  SetUrlCacheGroupAttributeA, (GROUPID, DWORD, DWORD, LPINTERNET_CACHE_GROUP_INFOA, LPVOID));
UDECL(BOOL,  SetUrlCacheGroupAttributeW, (GROUPID, DWORD, DWORD, LPINTERNET_CACHE_GROUP_INFOW, LPVOID));
UDECL(BOOL,  GetUrlCacheGroupAttributeA, (GROUPID, DWORD, DWORD, LPINTERNET_CACHE_GROUP_INFOA, LPDWORD, LPVOID));
UDECL(BOOL,  GetUrlCacheGroupAttributeW, (GROUPID, DWORD, DWORD, LPINTERNET_CACHE_GROUP_INFOW, LPDWORD, LPVOID));
/* HTTP push / dependency handles (urlmon plumbing) */
typedef struct { GUID TransportSettingId; GUID BrokerEventId; } gs_push_setting;
typedef struct { BOOL ChannelStatusValid; DWORD ChannelStatus; } gs_push_status;
UDECL(DWORD, HttpPushEnable, (HINTERNET, gs_push_setting *, HANDLE *));
UDECL(DWORD, HttpPushWait, (HANDLE, DWORD, gs_push_status *));
UDECL(void,  HttpPushClose, (HANDLE));
UDECL(DWORD, HttpOpenDependencyHandle, (HINTERNET, BOOL, HANDLE *));
UDECL(void,  HttpCloseDependencyHandle, (HANDLE));
UDECL(DWORD, HttpDuplicateDependencyHandle, (HANDLE, HANDLE *));
UDECL(DWORD, HttpIndicatePageLoadComplete, (HANDLE));
UDECL(void,  GetProxyDllInfo, (void **, void **));
UDECL(void,  InternetFreeProxyInfoList, (void *));

/* ---- ordinal-only exports (PDB names from the corpus; see docs/research/01_export_map.md) ---------- */
typedef BOOL    (WINAPI *gs_DoConnectoidsExist)(void);                                     /* #101 */
typedef BOOL    (WINAPI *gs_GetDiskInfoA)(LPCSTR, DWORD *, ULARGE_INTEGER *, ULARGE_INTEGER *); /* #102 */
typedef BOOL    (WINAPI *gs_DavA)(LPCSTR, LPCSTR, LPBOOL, HWND, LPVOID);                    /* #104 */
typedef BOOL    (WINAPI *gs_DavW)(LPCWSTR, LPCWSTR, LPBOOL, HWND, LPVOID);                  /* #105 */
typedef BOOL    (WINAPI *gs_ImportCookieFileA)(LPCSTR);                                     /* #108 */
typedef BOOL    (WINAPI *gs_ExportCookieFileA)(LPCSTR, BOOL);                               /* #109 */
typedef BOOL    (WINAPI *gs_ImportCookieFileW)(LPCWSTR);                                    /* #110 */
typedef BOOL    (WINAPI *gs_ExportCookieFileW)(LPCWSTR, BOOL);                              /* #111 */
typedef BOOL    (WINAPI *gs_IsDuoStream)(void);                                             /* #112 */
typedef BOOL    (WINAPI *gs_IdlA)(LPCSTR, LPCSTR);                                          /* #116 */
typedef BOOL    (WINAPI *gs_IdlW)(LPCWSTR, LPCWSTR);                                        /* #117 */
typedef int     (WINAPI *gs_FindP3PPolicySymbol)(const char *);                             /* #118 */
typedef DWORD   (WINAPI *gs_GetP3PPolicy)(void *, void *, void *, void *);                  /* #120-#123 */
typedef DWORD   (WINAPI *gs_InternalInternetGetCookie)(void *, void *, void *);             /* #346 */
typedef DWORD   (WINAPI *gs_ReadGuidsForConnectedNetworks)(void *, void *, void *, void *, void *, void *); /* #401 */
typedef DWORD   (WINAPI *gs_AutoProxyGetProxyForUrl)(void *, void *);                       /* #402 */
typedef HRESULT (WINAPI *gs_GetCacheServerConnection)(void **);                             /* #410 */
typedef HRESULT (WINAPI *gs_CreateCacheServerRpcBinding)(void *, void **);                  /* #411 */
typedef HRESULT (WINAPI *gs_SetGlobalJetParameters)(void);                                  /* #413 */
typedef HRESULT (WINAPI *gs_IsLanConnection)(BOOL *);                                       /* #420 */
typedef HRESULT (WINAPI *gs_IsDialUpConnection)(BOOL *);                                    /* #421 */

/* wininet ordinal -> pointer (NULL if missing) */
static inline FARPROC gs_ord(unsigned ord) { return t_proc_ord("wininet.dll", ord); }
#define GS_ORD(type, n) ((type)gs_ord(n))
#define REQUIRE_ORD(n) do { if (!gs_ord(n)) { t_skip("missing wininet ordinal #%u", (unsigned)(n)); return; } } while (0)

/* ---- export table rows (gs_exptab.c is generated from tools/<module>_exports.json) ------------------------- */
typedef struct { const char *name; unsigned ord; unsigned rva; const char *forwarder; } gs_export;
extern const gs_export gs_exp_wininet[];  extern const size_t gs_exp_wininet_n;
extern const gs_export gs_exp_urlmon[];   extern const size_t gs_exp_urlmon_n;
extern const gs_export gs_exp_winhttp[];  extern const size_t gs_exp_winhttp_n;
extern const gs_export gs_exp_sspicli[];  extern const size_t gs_exp_sspicli_n;
extern const gs_export gs_exp_schannel[]; extern const size_t gs_exp_schannel_n;
extern const gs_export gs_exp_crypt32[];  extern const size_t gs_exp_crypt32_n;
extern const gs_export gs_exp_ws2_32[];   extern const size_t gs_exp_ws2_32_n;

/* ---- small helpers ------------------------------------------------------------------------------- */
/* memory filled with a recognisable byte so "untouched" can be asserted */
static inline void gs_fill(void *p, size_t n) { memset(p, 0xA5, n); }
static inline int gs_untouched(const void *p, size_t n) {
    const unsigned char *b = (const unsigned char *)p;
    for (size_t i = 0; i < n; i++) if (b[i] != 0xA5) return 0;
    return 1;
}
static inline int gs_all_zero(const void *p, size_t n) {
    const unsigned char *b = (const unsigned char *)p;
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}
/* GetLastError seeds used to prove "unchanged" vs "overwritten" */
static const DWORD gs_seeds[] = { 0, 1, 87, 0x4242, 12007, 0xDEADBEEFu };
#define GS_NSEEDS (sizeof gs_seeds / sizeof gs_seeds[0])

/* Session/connect handles that never touch the network until a request is sent. */
HINTERNET gs_session(void);                 /* InternetOpenA DIRECT, cached for the process; never closed by tests */
HINTERNET gs_connect_http(HINTERNET s);     /* InternetConnectA 127.0.0.1:9 HTTP (no traffic) */
HINTERNET gs_request(HINTERNET c, const char *path);  /* HttpOpenRequestA GET (no traffic) */
/* Run fn(arg) on a worker thread and wait at most ms; returns 1 if it completed. */
typedef void (*gs_fn)(void *);
int gs_bounded(gs_fn fn, void *arg, DWORD ms);
/* [base, base+size) of a loaded module, from its in-memory PE header */
int gs_module_range(HMODULE h, ULONG_PTR *lo, ULONG_PTR *hi);
#endif
