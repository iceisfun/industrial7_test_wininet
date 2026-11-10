/* ac.h - status-callback recorder shared by the async_callbacks area (prefix ac_).
 *
 * Every test resets the recorder (ac_begin), installs ac_cb (ANSI) or ac_cbw (Unicode) on a session, drives
 * WinINet against an in-process loopback server and then inspects the recorded INTERNET_STATUS_* events.
 * WinINet hands the callback a COPY of the status information (InternetIndicateStatus memcpy's it into a
 * local/heap buffer before the call, [D wininet!InternetIndicateStatus@0x5e500]), so the recorder copies at most
 * AC_INFO bytes of it and never keeps the pointer.
 *
 * Async completion data (InternetReadFile's lpdwNumberOfBytesRead, buffers) must outlive the call: the tests
 * use static storage for anything a worker thread may write after the API returned ERROR_IO_PENDING.
 */
#ifndef AC_H
#define AC_H
#include "t.h"
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

#ifndef INTERNET_STATUS_COOKIE_SENT
#define INTERNET_STATUS_COOKIE_SENT 320
#endif
#ifndef INTERNET_STATUS_COOKIE_RECEIVED
#define INTERNET_STATUS_COOKIE_RECEIVED 321
#endif
#define AC_ST_330 330   /* 0x14a, raised from HttpSendRequest_Start (docs/research/02 section 13) */

/* t.h's EXPECT_EQ evaluates its operands twice (once for the check, once for the message). Many checks here
 * compare the result of a call with side effects (InternetSetStatusCallback returns the previous callback),
 * so this area uses a single-evaluation version. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { ULONG_PTR a_ = (ULONG_PTR)(a), b_ = (ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", (unsigned long long)a_, (unsigned long long)b_); } while (0)

/* IncomingCookieState / OutgoingCookieState (wininet.h of IE6+, not in mingw): status 321 / 320 payloads */
typedef struct { int cSession, cPersistent, cAccepted, cLeashed, cDowngraded, cBlocked; const char *pszLocation; } ac_in_cookie_state;
typedef struct { int cSent, cSuppressed; const char *pszLocation; } ac_out_cookie_state;

#define AC_MAXEV  1024
#define AC_INFO   160

typedef struct {
    HINTERNET h;          /* hInternet argument */
    DWORD_PTR ctx;        /* dwContext argument */
    DWORD st;             /* dwInternetStatus */
    DWORD len;            /* dwStatusInformationLength */
    int has_info;         /* lpvStatusInformation != NULL */
    DWORD tid;            /* thread that delivered it */
    int wide;             /* delivered to the W callback */
    unsigned char info[AC_INFO];  /* first bytes of the status information */
    DWORD seq;            /* global arrival index */
} ac_ev;

/* contexts used everywhere */
#define CTX_SES ((DWORD_PTR)0x5E550001)
#define CTX_CON ((DWORD_PTR)0xC0440002)
#define CTX_REQ ((DWORD_PTR)0x4E030003)
#define CTX_URL ((DWORD_PTR)0x0B110004)
#define CTX_ALT ((DWORD_PTR)0xA17A0005)

void CALLBACK ac_cb(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len);
void CALLBACK ac_cbw(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len);
void CALLBACK ac_cb2(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len);  /* second, distinguishable callback */

/* optional hook run inside the callback after recording (reentrancy tests); reset by ac_begin */
typedef void (*ac_hook_fn)(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len);
extern volatile ac_hook_fn ac_hook;
extern DWORD ac_main_tid;

void ac_begin(void);                        /* reset recorder, record main thread id */
int  ac_count(void);                        /* events so far */
int  ac_get(int i, ac_ev *out);             /* copy of event i; 0 if out of range */
int  ac_count_st(DWORD st);                 /* events with that status (any context) */
int  ac_count_st_ctx(DWORD st, DWORD_PTR ctx);
int  ac_find(DWORD st, DWORD_PTR ctx, int from);   /* index of first event st (ctx 0 = any) at or after from, -1 */
int  ac_find_h(DWORD st, HINTERNET h, int from);   /* by handle */
int  ac_count_cb2(void);                    /* events delivered to ac_cb2 */
/* wait until at least n events with status st (ctx 0 = any) exist; 1 reached, 0 timeout */
int  ac_wait_st(DWORD st, DWORD_PTR ctx, int n, DWORD ms);
/* REQUEST_COMPLETE helpers: wait for the k-th (1-based) completion on ctx, return its INTERNET_ASYNC_RESULT */
int  ac_wait_complete(DWORD_PTR ctx, int k, DWORD ms, INTERNET_ASYNC_RESULT *res);
/* "60,10,11,..." of statuses for ctx (0 = all), skipping statuses in skip[] (0-terminated, may be NULL) */
const char *ac_seq(DWORD_PTR ctx, const DWORD *skip);
const char *ac_seq_range(DWORD_PTR ctx, int from, int to, const DWORD *skip);
void ac_dump(const char *tag);              /* t_note every event (status, ctx, len, tid, info) */
/* 1 if statuses a appears before b for ctx (both present) */
int  ac_before(DWORD a, DWORD b, DWORD_PTR ctx);
/* all events of ctx delivered on thread tid? (returns count of events NOT on tid) */
int  ac_count_not_tid(DWORD_PTR ctx, DWORD tid);
int  ac_count_tid(DWORD_PTR ctx, DWORD tid);
DWORD ac_info_dword(const ac_ev *e);
DWORD_PTR ac_info_ptr(const ac_ev *e);

/* sessions */
HINTERNET ac_open(DWORD flags);             /* InternetOpenA("ac-agent", DIRECT, flags) + 5 s timeouts */
HINTERNET ac_open_cb(DWORD flags, INTERNET_STATUS_CALLBACK cb);  /* + callback installed */
/* close h and wait (bounded) until its HANDLE_CLOSING (ctx) is seen when a callback is installed */
void ac_close_wait(HINTERNET h, DWORD_PTR ctx);
/* drain: wait until no event arrived for quiet_ms (bounded by max_ms) */
void ac_quiesce(DWORD quiet_ms, DWORD max_ms);

/* async request runner: sends and waits; returns 1 if the request completed OK. *pending = 997 seen. */
int  ac_send_wait(HINTERNET hreq, DWORD_PTR ctx, const char *hdrs, void *opt, DWORD optn, int *pending, DWORD *err);
/* read the whole body of an async request handle (waits for completions); returns bytes, -1 on error */
long ac_read_all_async(HINTERNET hreq, DWORD_PTR ctx, char *buf, size_t cap, int *npending);
DWORD ac_status_code(HINTERNET hreq);

/* one session/connect/request triple against a loopback server */
typedef struct { srv *s; HINTERNET hi, hc, hr; DWORD sflags; } ac_flow;
/* starts the server (script steps; NULL = built-in 200 hello), session (sflags) with callback cb (may be NULL),
 * connect (CTX_CON) and request (verb, path, rflags, CTX_REQ). Returns 0 on failure (test already skipped/failed). */
int  ac_flow_open(ac_flow *f, const srv_step *steps, int nsteps, DWORD sflags, INTERNET_STATUS_CALLBACK cb,
                  const char *verb, const char *path, DWORD rflags);
/* closes request, connect (waiting for their HANDLE_CLOSING when cb set), session, stops the server */
void ac_flow_close(ac_flow *f);

#define START_OR_SKIP(cfgp, sp) do { int rc_ = srv_start((cfgp), (sp)); if (rc_) { t_skip("server unavailable: %s", srv_strerror(rc_)); return; } } while (0)
#define SRV_OR_SKIP(s, expr) do { (s) = (expr); if (!(s)) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; } } while (0)
#define REQ_ASYNC_API() do { REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetConnectA)); REQUIRE(U(HttpOpenRequestA)); \
    REQUIRE(U(HttpSendRequestA)); REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetReadFile)); REQUIRE(U(InternetCloseHandle)); } while (0)
#endif
