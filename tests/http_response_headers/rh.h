/* rh.h - helpers for the http_response_headers area (prefix rh_ / hqi_ / rsp_ / rqh_).
 *
 * Every test starts its own loopback server (common/srv.h) that answers with raw bytes, opens a WinINet
 * request with InternetConnectA/HttpOpenRequestA (DIRECT, T_INET_FRESH, no auto redirect, no auth),
 * sends it, and then interrogates HttpQueryInfoA/W. The DLL under test is never linked.
 *
 * Evidence tags used in comments: [D] decomp of Win10 wininet 11.0.19041 (Corpus Explorer), [W10] observed on
 * the local Win10 22H2 VM (results/win10/http_response_headers.txt), [K] general WinINet knowledge.
 */
#ifndef RH_H
#define RH_H
#include "t.h"
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

/* RELOAD|NO_CACHE_WRITE|PRAGMA_NOCACHE|NO_UI|NO_COOKIES + NO_AUTO_REDIRECT + NO_AUTH */
#define RH_FLAGS (T_INET_FRESH | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_AUTH)

typedef struct {
    srv *s;
    HINTERNET hi, hc, hr;
    srv_step st[8];
    srv_script sc;
    BOOL sent;       /* HttpSendRequestA result */
    DWORD err;       /* GetLastError after HttpSendRequestA (0 on success) */
} rh_t;

/* Start a server with a custom script (kept alive for all connections). 0 = skipped (t_skip done). */
int  rh_start(rh_t *c, const srv_step *steps, int n);
/* Session + connect + HttpOpenRequestA(verb, path, version NULL) with flags (0 -> RH_FLAGS). 0 = failed (CHECK done). */
int  rh_open(rh_t *c, const char *verb, const char *path, DWORD flags);
int  rh_open_v(rh_t *c, const char *verb, const char *path, const char *version, DWORD flags);
/* HttpSendRequestA(hr, hdrs, -1, opt, optlen); records sent/err. */
BOOL rh_send(rh_t *c, const char *hdrs, const void *opt, DWORD optlen);
/* Server answers the request on every connection with raw bytes, then closes. Starts, opens, sends.
 * Returns 0 if the test was skipped (server unavailable). c->sent / c->err describe HttpSendRequest. */
int  rh_raw(rh_t *c, const char *verb, const void *raw, size_t n);
#define RH_RAW(c, verb, lit) rh_raw((c), (verb), (lit), sizeof(lit) - 1)
/* As rh_raw but the request is not sent (caller sends). */
int  rh_raw_nosend(rh_t *c, const char *verb, const void *raw, size_t n);
void rh_close(rh_t *c);
/* Read the whole body of c->hr into buf (NUL-terminated); returns bytes. */
size_t rh_body(rh_t *c, char *buf, size_t cap);

/* ---- query helpers. Results live in 8 rotating 512 KB buffers. */
extern DWORD rh_err;   /* GetLastError of the last query (0 on success) */
extern DWORD rh_len;   /* *lpdwBufferLength after the last query */
extern BOOL  rh_ok;
/* HttpQueryInfoA(level) with a 512 KB buffer. NULL on failure. idx may be NULL. */
const char *rh_qa(HINTERNET h, DWORD level, DWORD *idx);
/* HttpQueryInfoA(HTTP_QUERY_CUSTOM | mods) for name. */
const char *rh_qac(HINTERNET h, const char *name, DWORD mods, DWORD *idx);
/* HttpQueryInfoW(level), converted to char (WideCharToMultiByte CP_ACP). rh_len = W byte count. */
const char *rh_qw(HINTERNET h, DWORD level, DWORD *idx);
const char *rh_qwc(HINTERNET h, const char *name, DWORD mods, DWORD *idx);
/* raw W result (wide) of the last rh_qw / rh_qwc */
const WCHAR *rh_lastw(void);
/* FLAG_NUMBER / NUMBER64 / SYSTEMTIME (A). level without the flag; returns success */
BOOL rh_qnum(HINTERNET h, DWORD level, DWORD *out);
BOOL rh_qnum64(HINTERNET h, DWORD level, ULONGLONG *out);
BOOL rh_qtime(HINTERNET h, DWORD level, SYSTEMTIME *out);
BOOL rh_qnumc(HINTERNET h, const char *name, DWORD *out);
BOOL rh_qnum64c(HINTERNET h, const char *name, ULONGLONG *out);
BOOL rh_qtimec(HINTERNET h, const char *name, SYSTEMTIME *out);
/* raw call: HttpQueryInfoA(h, level, buf, &len (in: *len), idx); sets rh_err/rh_len/rh_ok */
BOOL rh_callA(HINTERNET h, DWORD level, void *buf, DWORD len, DWORD *idx);
BOOL rh_callW(HINTERNET h, DWORD level, void *buf, DWORD len, DWORD *idx);

/* ---- expectation helpers (want == NULL: expect ERROR_HTTP_HEADER_NOT_FOUND) */
void rh_expect_a(HINTERNET h, DWORD level, const char *want, const char *file, int line);
void rh_expect_w(HINTERNET h, DWORD level, const char *want, const char *file, int line);
void rh_expect_c(HINTERNET h, const char *name, const char *want, const char *file, int line); /* custom, A and W */
void rh_expect_err(HINTERNET h, DWORD level, DWORD err, int wide, const char *file, int line);
void rh_expect_cerr(HINTERNET h, const char *name, DWORD mods, DWORD err, const char *file, int line);
#define EXPECT_QA(h, l, w)        rh_expect_a((h), (l), (w), __FILE__, __LINE__)
#define EXPECT_QW(h, l, w)        rh_expect_w((h), (l), (w), __FILE__, __LINE__)
#define EXPECT_Q(h, l, w)         do { rh_expect_a((h), (l), (w), __FILE__, __LINE__); rh_expect_w((h), (l), (w), __FILE__, __LINE__); } while (0)
#define EXPECT_QC(h, n, w)        rh_expect_c((h), (n), (w), __FILE__, __LINE__)
#define EXPECT_QERR(h, l, e)      rh_expect_err((h), (l), (e), 0, __FILE__, __LINE__)
#define EXPECT_QERRW(h, l, e)     rh_expect_err((h), (l), (e), 1, __FILE__, __LINE__)
#define EXPECT_QERR2(h, l, e)     do { rh_expect_err((h), (l), (e), 0, __FILE__, __LINE__); rh_expect_err((h), (l), (e), 1, __FILE__, __LINE__); } while (0)
#define EXPECT_QCERR(h, n, m, e)  rh_expect_cerr((h), (n), (m), (e), __FILE__, __LINE__)

/* send must have succeeded, else skip the rest of the test with a FAIL */
#define RH_SENT_OR_FAIL(c) do { if (!(c)->sent) { t_check(0, __FILE__, __LINE__, "HttpSendRequest", "err=%lu %s", (c)->err, t_inet_errname((c)->err)); rh_close(c); return; } } while (0)

/* Known-header table: name (NULL for the synthetic levels 18-22, 45, 73, 74) and the modifier mask:
 * a modifier bit in 0xF8000000 that is not in the mask gives ERROR_HTTP_INVALID_QUERY_REQUEST (12154) [D HttpQueryInfoA]. */
typedef struct { const char *name; DWORD mask; } rh_known_t;
extern const rh_known_t rh_known[96];

/* escaped printable copy for messages (rotating static) */
const char *rh_esc(const char *p, size_t n);
/* GetACP() == 1252 (byte -> UTF-16 mapping predictable for 0x80..0xFF) */
int rh_acp1252(void);
#endif
