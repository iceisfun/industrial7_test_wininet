/* hep.h - shared helpers for the http_edge_protocol area: protocol robustness of the WinINet HTTP client against
 * scripted loopback servers (common/srv.h). Test-name prefix: hep_.
 *
 * Most response-side tests are table rows: the server sends a raw byte string, the client does one GET, and the
 * outcome is folded into a compact signature string ("ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi"). The expected
 * signature of each row is the one measured on genuine Windows 10 (see EVIDENCE.md); a row whose expectation is
 * NULL only records the observation with t_note ("OBS ...").
 */
#ifndef HEP_H
#define HEP_H
#include "t.h"
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

/* RELOAD | NO_CACHE_WRITE | PRAGMA_NOCACHE | NO_UI | NO_COOKIES (+ no auto redirect) */
#define HEP_F   (T_INET_FRESH | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_KEEP_CONNECTION)
#define HEP_F_REDIR (T_INET_FRESH)

#ifndef INTERNET_OPTION_CODEPAGE_PATH
#define INTERNET_OPTION_CODEPAGE_PATH 100
#endif
#ifndef INTERNET_OPTION_CODEPAGE_EXTRA
#define INTERNET_OPTION_CODEPAGE_EXTRA 101
#endif
#ifndef INTERNET_OPTION_IDN
#define INTERNET_OPTION_IDN 102
#endif
#ifndef INTERNET_OPTION_CODEPAGE
#define INTERNET_OPTION_CODEPAGE 68
#endif
#ifndef ERROR_HTTP_INVALID_SERVER_RESPONSE
#define ERROR_HTTP_INVALID_SERVER_RESPONSE 12152
#endif
#ifndef HTTP_ADDREQ_FLAG_ALLOW_EMPTY_VALUES
#define HTTP_ADDREQ_FLAG_ALLOW_EMPTY_VALUES 0x04000000
#endif

/* ---------------------------------------------------------------- servers */
/* Per-connection SO_RCVTIMEO/SO_SNDTIMEO of every hep server. Win10 VM (hep_zz_timing_probe): WinINet keeps the
 * keep-alive socket pooled after InternetCloseHandle, the server thread then sits in recv() for the next head and
 * shutdown(SD_BOTH) does not wake it, so srv_stop() waited its full 3 s per server. A 1 s receive timeout bounds that
 * cost; requests inside one test follow each other within milliseconds (hep_conn.c servers use 1 s, servers that wait on
 * the client use hep_io_timeout_next). */
#define HEP_IO_TIMEOUT 300
/* one-shot override for the next hep_start*() (tests whose server waits on the client for longer) */
void hep_io_timeout_next(DWORD ms);
/* A server owning its (heap) script; freed by hep_stop. */
typedef struct hep_srv {
    srv *s;
    srv_step *steps; int nsteps;
    srv_script sc;
    void *blob;          /* optional heap data referenced by the steps (raw responses) */
} hep_srv;
/* steps copied; nsteps entries. lifetime/io timeouts default (20 s / 5 s). Returns NULL (and t_skip) on failure. */
hep_srv *hep_start(const srv_step *st, int n);
hep_srv *hep_start_v4(const srv_step *st, int n, int v4_only);
/* Read one head, send raw bytes (n bytes, may contain NUL), then mode: 0 graceful close, 1 shut-wr then drain,
 * 2 RST, 3 loop back (keep-alive: read next head, send the same bytes again). */
hep_srv *hep_start_raw(const void *raw, size_t n, int mode);
/* Read one head, send raw, then on the same connection read the next head and send raw2 (both may contain NUL). */
hep_srv *hep_start_raw2(const void *raw, size_t n, const void *raw2, size_t n2);
/* Every request: read head + body, reply 200 "ok", keep-alive. */
hep_srv *hep_start_ok(void);
void hep_stop(hep_srv *h);

/* ---------------------------------------------------------------- one request */
typedef struct {
    BOOL ok;           /* HttpSendRequest (or InternetOpenUrl) result */
    DWORD err;         /* GetLastError when !ok */
    int status;        /* STATUS_CODE|NUMBER, -1 if the query failed */
    DWORD status_err;  /* error of that query */
    int status_qfail;  /* the STATUS_CODE|NUMBER query failed (signature "st=?<err>") */
    char ver[64];      /* HTTP_QUERY_VERSION or "?<err>" */
    char txt[128];     /* HTTP_QUERY_STATUS_TEXT or "?<err>" */
    char hval[1024];   /* value of the custom header asked for (hep_req.qname) or "?<err>" */
    char cl[64];       /* HTTP_QUERY_CONTENT_LENGTH or "?<err>" */
    int read_ok;       /* InternetReadFile loop ended without error */
    DWORD read_err;
    char body[8192];
    size_t nbody;      /* bytes read (may exceed sizeof body - 1; body keeps the first part) */
    DWORD ms;          /* wall time of send+read */
} hep_res;

typedef struct {
    const char *agent;     /* default "hep" */
    const char *host;      /* default "127.0.0.1" */
    const char *verb;      /* default "GET" */
    const char *obj;       /* default "/" */
    const char *ver;       /* NULL */
    const char *hdrs;      /* HttpSendRequest headers (-1 length) */
    const void *opt; DWORD optlen;
    DWORD flags;           /* default HEP_F */
    DWORD timeout_ms;      /* session timeouts, default 3000 */
    const char *qname;     /* custom header to query into hval */
    int keep_handles;      /* do not close handles: caller uses hep_conn* */
} hep_req;

/* Session+connect+request on the server, send, query, read. Closes the handles. */
void hep_do(hep_srv *h, const hep_req *rq, hep_res *r);
/* Request on an existing connect handle (keep-alive tests). */
void hep_do_on(HINTERNET hc, const hep_req *rq, hep_res *r);
/* InternetOpenUrlA on a session, query, read. */
void hep_openurl(HINTERNET hi, const char *url, const char *hdrs, DWORD flags, const char *qname, hep_res *r);
void hep_openurl_w(HINTERNET hi, const WCHAR *url, DWORD flags, hep_res *r);
/* Signature string of a result (rotating static buffers). what: bit0 ver, bit1 txt, bit2 hval, bit3 cl. */
const char *hep_sig(const hep_res *r, unsigned what);
#define HEP_SIG_STD 3u     /* ver + txt */

/* Escape bytes for a NOTE/signature: \r \n \t \0 \xNN (rotating buffers, truncated at cap 1500 output chars). */
const char *hep_esc(const void *p, size_t n);

/* ---------------------------------------------------------------- sessions */
HINTERNET hep_session(const char *agent, DWORD timeout_ms);              /* DIRECT */
HINTERNET hep_proxy_session(hep_srv *h, const char *agent);             /* PROXY http=127.0.0.1:port, no bypass */
HINTERNET hep_connect(HINTERNET hi, hep_srv *h);                         /* 127.0.0.1:port */
int  hep_keeper_on(void);      /* keep one extra session open for the process lifetime (default: on) */
void hep_keeper_off(void);
void hep_keeper_auto(int on);

/* ---------------------------------------------------------------- recorder helpers */
const char *hep_names(srv *s, int i);          /* "A|B|C" header names in order */
const char *hep_raw(srv *s, int i);            /* raw head, escaped */
const char *hep_hostport(hep_srv *h);          /* "127.0.0.1:port" */
void hep_dump(srv *s, int i);

/* Run fn on a worker thread; a hang beyond ms fails the test (thread leaked). */
int  hep_guard(const char *name, void (*fn)(void), DWORD ms);
#define GTEST(n, ms) static void gbody_##n(void); TEST(n) { hep_guard(#n, gbody_##n, (ms)); } static void gbody_##n(void)

#define HEP_REQUIRE_HTTP() do { REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetConnectA)); REQUIRE(U(HttpOpenRequestA)); \
    REQUIRE(U(HttpSendRequestA)); REQUIRE(U(InternetReadFile)); REQUIRE(U(HttpQueryInfoA)); } while (0)
#define HEP_SRV(var, expr) hep_srv *var = (expr); if (!var) return
#define EXPECT_HDR(s, i, name, want) EXPECT_STR(srv_req_header((s), (i), (name)), (want))
#define EXPECT_NOHDR(s, i, name) CHECKF(srv_req_header_index((s), (i), (name)) < 0, "header %s present: %s", (name), srv_req_header((s), (i), (name)))

/* Compare a signature with the Win10 expectation; NULL expectation = observation only. */
void hep_expect_sig(const char *tag, const char *got, const char *want, const char *file, int line);
#define EXPECT_SIG(tag, got, want) hep_expect_sig((tag), (got), (want), __FILE__, __LINE__)

/* Response-table row runner: raw response (n bytes), mode as hep_start_raw, signature bits, expectation. */
void hep_rcase(const char *tag, const char *raw, size_t n, int mode, const char *qname, unsigned what, const char *want);
#define RCASE(name, raw, want) TEST(hep_rsp_##name) { HEP_REQUIRE_HTTP(); hep_rcase(#name, raw, sizeof(raw) - 1, 0, NULL, HEP_SIG_STD, want); }
#define RCASEH(name, raw, qn, want) TEST(hep_hdr_##name) { HEP_REQUIRE_HTTP(); hep_rcase(#name, raw, sizeof(raw) - 1, 0, qn, 7u, want); }
#define RCASECL(name, raw, want) TEST(hep_cl_##name) { HEP_REQUIRE_HTTP(); hep_rcase(#name, raw, sizeof(raw) - 1, 0, NULL, 8u, want); }
#endif
