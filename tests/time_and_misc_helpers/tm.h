/* Shared helpers for the time_and_misc_helpers area.
 * Evidence tags used in comments: [D fn] = Win10 19041 decomp (corpus explorer), [VM] = observed on the
 * Win10 22H2 guest, [K] = documented/well-known behaviour. See EVIDENCE.md. */
#ifndef TM_H
#define TM_H
#include "t.h"
#include <wincrypt.h>
#include <wininet.h>

/* Exports that mingw does not declare (or declares only in winineti.h): local prototypes. */
UDECL(BOOL,  InternetGetSecurityInfoByURLA, (LPSTR, PCCERT_CHAIN_CONTEXT *, DWORD *));
UDECL(BOOL,  InternetGetSecurityInfoByURLW, (LPCWSTR, PCCERT_CHAIN_CONTEXT *, DWORD *));
UDECL(BOOL,  InternetGetSecurityInfoByURL,  (LPSTR, PCCERT_CHAIN_CONTEXT *, DWORD *));
UDECL(BOOL,  GetUrlCacheHeaderData, (DWORD, DWORD *));
UDECL(BOOL,  SetUrlCacheHeaderData, (DWORD, DWORD));
UDECL(BOOL,  IncrementUrlCacheHeaderData, (DWORD, DWORD *));
UDECL(void,  InternetFreeCookies, (void *, DWORD));
UDECL(DWORD, InternetGetCookieEx2, (PCWSTR, PCWSTR, DWORD, void **, PDWORD));
UDECL(BOOL,  InternetAlgIdToStringA, (DWORD, LPSTR, DWORD *, DWORD));
UDECL(BOOL,  InternetAlgIdToStringW, (DWORD, LPWSTR, DWORD *, DWORD));
UDECL(BOOL,  InternetSecurityProtocolToStringA, (DWORD, LPSTR, DWORD *, DWORD));
UDECL(BOOL,  InternetSecurityProtocolToStringW, (DWORD, LPWSTR, DWORD *, DWORD));
UDECL(DWORD, _GetFileExtensionFromUrl, (LPSTR, DWORD, LPSTR, DWORD *));
UDECL(DWORD, HttpIsHostHstsEnabled, (LPCWSTR, BOOL *));
UDECL(BOOL,  InternetFortezzaCommand, (DWORD, HWND, DWORD_PTR));
UDECL(BOOL,  InternetQueryFortezzaStatus, (DWORD *, DWORD_PTR));
UDECL(void,  InternetAutodialCallback, (DWORD, LPCVOID));
UDECL(BOOL,  InternetGoOnline, (LPSTR, HWND, DWORD));
UDECL(BOOL,  InternetSetDialState, (LPCSTR, DWORD, DWORD));
UDECL(DWORD, InternetDial, (HWND, LPSTR, DWORD, DWORD_PTR *, DWORD));
UDECL(DWORD, InternetConfirmZoneCrossing, (HWND, LPSTR, LPSTR, BOOL));
UDECL(BOOL,  InternetTimeFromSystemTime, (const SYSTEMTIME *, DWORD, LPSTR, DWORD));
UDECL(BOOL,  InternetTimeToSystemTime, (LPCSTR, SYSTEMTIME *, DWORD));
UDECL(INTERNET_STATUS_CALLBACK, InternetSetStatusCallback, (HINTERNET, INTERNET_STATUS_CALLBACK));
/* ordinal-only exports: by number */
typedef BOOL (WINAPI *IsDomainLegalCookieDomainA_pfn)(LPCSTR, LPCSTR);
typedef BOOL (WINAPI *IsDomainLegalCookieDomainW_pfn)(LPCWSTR, LPCWSTR);

/* INTERNET_COOKIE2 layout (documented; mingw lacks it in older headers) */
typedef struct {
    PWSTR pwszName; PWSTR pwszValue; PWSTR pwszDomain; PWSTR pwszPath;
    DWORD dwFlags; FILETIME ftExpires; BOOL fExpiresSet;
} tm_cookie2;

/* Fill memory with a recognisable byte so "untouched" can be asserted. */
static inline void tm_fill(void *p, size_t n) { memset(p, 0xAB, n); }
static inline int tm_is_filled(const void *p, size_t n) {
    const unsigned char *b = (const unsigned char *)p; for (size_t i = 0; i < n; i++) if (b[i] != 0xAB) return 0; return 1;
}

/* Run fn(arg) on a worker thread with a bound (safety net for calls that might block on UI).
 * Returns 1 if it finished in time, 0 if it timed out (the thread is left running and a NOTE is printed). */
typedef void (*tm_fn)(void *);
int tm_run_bounded(tm_fn fn, void *arg, DWORD ms);

/* proleptic Gregorian weekday, 0 = Sunday */
static inline int tm_weekday(int y, int m, int d) {
    static const int t[] = { 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };
    if (m < 3) y -= 1;
    return (y + y / 4 - y / 100 + y / 400 + t[m - 1] + d) % 7;
}
static inline int tm_leap(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }
static inline int tm_mdays(int y, int m) {
    static const int d[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    return m == 2 && tm_leap(y) ? 29 : d[m - 1];
}
extern const char *const tm_wk[7];
extern const char *const tm_mon[13];   /* index 1..12 */
#endif
