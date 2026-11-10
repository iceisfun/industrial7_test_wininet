/* ck.h - shared helpers for the cookies area (prefix ck_).
 *
 * Every cookie a test creates goes through ck_set, ck_setx or ck_track, which remembers (url, name, path, domain, flags)
 * and expires the cookie again in ck_cleanup() (called at the end of each test and at exit). Hosts are unique
 * per process (t_uniq_host: wininet<pid>n<seq><tag>.i7test.example); wire tests use 127.0.0.1 with a unique
 * path (cookies are not port-scoped). No test uses the network except the in-process loopback servers.
 */
#ifndef CK_H
#define CK_H
#include "t.h"
#include <stdlib.h>
#include <ctype.h>
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

#define CK_PAST "expires=Thu, 01-Jan-1970 00:00:01 GMT"

/* Documented but missing from mingw's wininet.h */
#ifndef INTERNET_SUPPRESS_COOKIE_PERSIST
#define INTERNET_SUPPRESS_COOKIE_PERSIST 0x03
#define INTERNET_SUPPRESS_COOKIE_PERSIST_RESET 0x04
#endif
UDECL(DWORD, InternetGetCookieEx2, (PCWSTR url, PCWSTR name, DWORD flags, INTERNET_COOKIE2 **cookies, PDWORD count));
UDECL(DWORD, InternetSetCookieEx2, (PCWSTR url, const INTERNET_COOKIE2 *cookie, PCWSTR p3p, DWORD flags, PDWORD state));
UDECL(VOID,  InternetFreeCookies,  (INTERNET_COOKIE2 *cookies, DWORD count));

/* names / urls (rotating static buffers) */
const char *ck_host(const char *tag);                       /* unique host */
const char *ck_url(const char *host, const char *path);     /* "http://" host path */
const char *ck_surl(const char *host, const char *path);    /* "https://" host path */
const char *ck_upath(const char *tag);                      /* unique path "/wininet_<pid>_<n>_<tag>" (no trailing /) */
const char *ck_date(int days);                              /* RFC 1123 "Wdy, DD Mon YYYY HH:MM:SS GMT", guest clock + days */
const char *ck_date_old(int days);                          /* Netscape "Wdy, DD-Mon-YYYY HH:MM:SS GMT" */
const WCHAR *ck_w(const char *s);                           /* ASCII -> UTF-16 (rotating buffers) */
const char  *ck_a(const WCHAR *s);                          /* UTF-16 -> ASCII (rotating) */

/* set: InternetSetCookieExA(url, name, data, flags, 0) + track for cleanup. Returns the Ex result (cookie state). *gle = GLE */
DWORD ck_setx(const char *url, const char *name, const char *data, DWORD flags, DWORD *gle);
/* InternetSetCookieA + track; returns BOOL */
BOOL  ck_set(const char *url, const char *name, const char *data);
/* Track something set some other way (wire, W API, child). attrs: extra attribute string ("path=/x; domain=h") or NULL */
void  ck_track(const char *url, const char *name, const char *attrs, DWORD flags);
void  ck_cleanup(void);

/* get: InternetGetCookieExA(url, name, buf, &size, flags, NULL). Returns the BOOL; *out = data ("" on failure);
 * ck_gle / ck_size hold GetLastError and the size written by the call. */
extern DWORD ck_gle, ck_size;
BOOL  ck_get(const char *url, const char *name, DWORD flags, char *out, DWORD cap);
const char *ck_gets(const char *url, const char *name, DWORD flags);   /* the string ("" when FALSE), rotating buffer */
/* token helpers on "a=1; b=2" strings */
int   ck_count(const char *s);                     /* number of "; "-separated items, 0 for "" */
int   ck_has(const char *s, const char *item);     /* exact item present */
int   ck_index(const char *s, const char *item);   /* position of item, -1 */

/* wire: one GET through InternetOpenUrlA on a fresh DIRECT session. flags are OR'ed with RELOAD|NO_CACHE_WRITE|PRAGMA_NOCACHE|NO_UI
 * (cookies on, unless the caller passes INTERNET_FLAG_NO_COOKIES). Returns the status code (0 on failure). */
int   ck_wire_get(HINTERNET session, const char *url, const char *hdrs, DWORD flags);
#define CK_WIRE_BASE (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_UI)
#define CK_START_OR_SKIP(cfgp, sp) do { int rc_ = srv_start((cfgp), (sp)); if (rc_) { t_skip("server unavailable: %s", srv_strerror(rc_)); return; } } while (0)
#endif
