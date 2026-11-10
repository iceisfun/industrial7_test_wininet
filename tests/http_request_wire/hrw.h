/* hrw.h - shared helpers for the http_request_wire area (what the WinINet client puts on the wire).
 * Every request goes to an in-process loopback server (common/srv.h); assertions read the server recorder.
 * Test-name prefix: hrw_. */
#ifndef HRW_H
#define HRW_H
#include "t.h"
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

/* Base request flags for wire tests: no cache read/write, no cookies, no UI (RELOAD is included: see EVIDENCE.md
 * for which default headers that adds). */
#define HRW_F      (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES)
/* Same without RELOAD (cache read allowed; tests then use a unique path so the cache can only miss). */
#define HRW_F_NORL (INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES)

#ifndef HTTP_ADDREQ_FLAG_ALLOW_EMPTY_VALUES
#define HTTP_ADDREQ_FLAG_ALLOW_EMPTY_VALUES 0x04000000
#endif
#ifndef HTTP_ADDREQ_FLAG_RESPONSE_HEADERS
#define HTTP_ADDREQ_FLAG_RESPONSE_HEADERS 0x02000000
#endif

typedef struct {
    srv *s;
    HINTERNET hi, hc, hr;
    BOOL ok;         /* result of the last send */
    DWORD err;       /* GetLastError after the last send (0 on success) */
    int status;      /* HTTP status after the last send (0 if unknown) */
    char body[4096]; /* response body read by hrw_finish */
    size_t nbody;
} hrw;

/* Default server: every request -> read body -> 200 "ok", keep-alive unless the request asked to close. */
srv *hrw_srv(void);
/* Server with a custom script (single script for every connection). */
srv *hrw_srv_steps(const srv_step *st, int n);
/* Server whose every request is handled by fn (SRV_CALL loop). */
srv *hrw_srv_call(srv_step_fn fn, void *user);

/* Open session(agent; DIRECT), connect to 127.0.0.1:port, open request. Returns 1 when all three handles exist. */
int  hrw_open(hrw *w, srv *s, const char *agent, const char *verb, const char *obj, const char *ver,
              const char *ref, const char **accept, DWORD flags);
/* Same, host chosen by the caller (e.g. "localhost", "::1"). */
int  hrw_open_host(hrw *w, srv *s, const char *agent, const char *host, const char *verb, const char *obj, DWORD flags);
/* HttpSendRequestA; fills ok/err/status. */
BOOL hrw_send(hrw *w, const char *hdrs, DWORD hlen, const void *opt, DWORD optlen);
/* Read the whole response body into w->body. */
void hrw_read(hrw *w);
/* Close request/connect/session handles (not the server). */
void hrw_close_handles(hrw *w);
/* Close everything and stop the server. */
void hrw_done(hrw *w);

/* One-shot: server default, GET-like request, send with headers/body, read response, wait for the recorder.
 * Returns 1 when the server recorded the request. */
int  hrw_simple(hrw *w, const char *agent, const char *verb, const char *obj, const char *ver, const char *ref,
                const char **accept, DWORD flags, const char *hdrs, const void *opt, DWORD optlen);

/* "Name1|Name2|..." of request i, exact casing and order (rotating static buffers). */
const char *hrw_names(srv *s, int i);
/* "127.0.0.1:<port>" */
const char *hrw_hostport(srv *s);
/* t_note the raw head of request i with CR/LF escaped. */
void hrw_dump(srv *s, int i);
/* Raw head of request i as a NUL-terminated string (rotating static buffers), or "" */
const char *hrw_raw(srv *s, int i);
/* Start a server and skip the test if it cannot. */
#define HRW_SRV_OR_SKIP(var, expr) srv *var = (expr); if (!var) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
#define HRW_REQUIRE_HTTP() do { REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetConnectA)); REQUIRE(U(HttpOpenRequestA)); \
    REQUIRE(U(HttpSendRequestA)); REQUIRE(U(InternetReadFile)); REQUIRE(U(HttpQueryInfoA)); } while (0)
#define EXPECT_NAMES(s, i, want) EXPECT_STR(hrw_names((s), (i)), (want))
#define EXPECT_HDR(s, i, name, want) EXPECT_STR(srv_req_header((s), (i), (name)), (want))
#define EXPECT_NOHDR(s, i, name) CHECKF(srv_req_header_index((s), (i), (name)) < 0, "header %s present: %s", (name), srv_req_header((s), (i), (name)))

/* proxy helper: session in PROXY mode pointing at the loopback server (no bypass). */
HINTERNET hrw_proxy_session(srv *s, const char *agent);

/* Global option helpers that restore state. */
int  hrw_get_dword_opt(HINTERNET h, DWORD opt, DWORD *v);
/* Run fn on a worker thread and wait at most ms. A hang is reported as a failure (the thread is leaked). */
int  hrw_guard(const char *name, void (*fn)(void), DWORD ms);
#define GTEST(n, ms) static void gbody_##n(void); TEST(n) { hrw_guard(#n, gbody_##n, (ms)); } static void gbody_##n(void)
extern volatile int hrw_trace;
#endif
