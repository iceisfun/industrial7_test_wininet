/* tnet.h - WinINet test helpers: deterministic sessions, unique cache/cookie names, cleanup registries.
 *
 * Determinism rules (see common/SRV.md "Proxy / WPAD"):
 *  - Every test session is INTERNET_OPEN_TYPE_DIRECT (t_inet_open). PRECONFIG pulls in the per-user IE
 *    proxy configuration, including auto-detect (WPAD, flag 0x8 in DefaultConnectionSettings, on by default).
 *    On the Win10 lab image auto-detect fails in < 1 ms (no DHCP 252, no DNS), but on another network it can
 *    take seconds (DNS wpad.<suffix>, DHCP INFORM) or route traffic through a proxy. Only proxy-area tests use
 *    PRECONFIG/PROXY, and those bound every call (worker thread + outer wait) and t_note timings.
 *  - Use IP literals (srv_url gives http://127.0.0.1:port/...). localhost resolves ::1 first (04 F2).
 *  - Requests that are not about caching/cookies use T_INET_FRESH so neither the URL cache nor the cookie jar
 *    is read or written.
 *  - Cache/cookie tests use names from t_uniq_* and register what they create (t_cache_track, t_cookie_track);
 *    the registries are flushed by t_net_cleanup() and at exit.
 * HINTERNET is passed as void * so this header can be used with either wininet.h or winhttp.h.
 */
#ifndef TNET_H
#define TNET_H
#include "t.h"

/* INTERNET_FLAG_RELOAD | NO_CACHE_WRITE | PRAGMA_NOCACHE | NO_UI | NO_COOKIES */
#define T_INET_FRESH 0x84080300u
/* + INTERNET_FLAG_NO_AUTO_REDIRECT (0x00200000) */
#define T_INET_FRESH_NOREDIR (T_INET_FRESH | 0x00200000u)

void  t_net_prepare(void);                   /* once per process; idempotent. Notes (read-only) proxy/TLS registry state. */
void *t_inet_open(const char *agent);        /* InternetOpenA(agent or "wininet_test", DIRECT) + 5 s timeouts; NULL on failure */
void *t_inet_open_ex(const char *agent, DWORD access, DWORD flags, DWORD timeout_ms);
void  t_inet_close(void *h);                 /* InternetCloseHandle, NULL ok */
/* InternetOpenUrlA(session, url, hdrs, flags) and read the whole body (up to cap-1 bytes, NUL-terminated).
 * Returns the HTTP status code (0 if InternetOpenUrl or the status query failed; *err = GetLastError then). */
int   t_http_get(void *session, const char *url, const char *hdrs, DWORD flags, char *body, size_t cap, size_t *len, DWORD *err);
/* Read everything from a request/url handle. Returns bytes read; *ok = InternetReadFile success. */
size_t t_inet_read_all(void *h, char *buf, size_t cap, int *ok);
/* OR flags into INTERNET_OPTION_SECURITY_FLAGS of a request handle (0x100 = IGNORE_UNKNOWN_CA, see 04 F8/F9). */
int   t_https_secflags(void *hreq, DWORD add);
const char *t_inet_errname(DWORD err);       /* "ERROR_INTERNET_CANNOT_CONNECT" etc. (static), or "?" */

/* unique names: rotating static buffers (16), safe for a few concurrent uses inside one test */
const char *t_uniq(const char *tag);                  /* "wininet_<pid>_<n>_<tag>" */
const char *t_uniq_host(const char *tag);             /* "wininet<pid>n<n><tag>.i7test.example" (lowercase alnum) */
const char *t_uniq_cookie_url(const char *tag);       /* "http://<t_uniq_host>/<tag>/" */
const char *t_uniq_cache_url(const char *tag);        /* "http://<t_uniq_host>/<tag>.txt", registered with t_cache_track */
void  t_cache_track(const char *url);                 /* DeleteUrlCacheEntryA(url) at cleanup */
void  t_cookie_track(const char *url, const char *name); /* expire cookie name for url at cleanup (InternetSetCookieA) */
void  t_net_cleanup(void);                            /* flush both registries now (also registered with atexit) */
#endif
