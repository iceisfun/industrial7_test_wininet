/* rs.h - shared helpers for the http_redirect_status area (prefix rs_).
 *
 * A "router" server: one SRV_CALL step that loops over requests on a connection and answers each one from a
 * table of routes (path -> status, headers, body). Header templates expand
 *   %P  this server's port          %A  the alt port (rs_router.alt_port, e.g. a second server)
 *   %N  next number of a /loop/<n> chain (n + 1)      %U  a unique token (rs_router.tok)      %%  percent
 * Everything listens on 127.0.0.1 / [::1]; no internet. Evidence classes are documented in EVIDENCE.md.
 */
#ifndef RS_H
#define RS_H
#include "t.h"
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

#ifndef ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION
#define ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION 12168
#endif

/* route flags */
#define RS_F_CLOSE     0x01   /* Connection: close + close after the reply */
#define RS_F_NOLEN     0x02   /* close-delimited body (no Content-Length), then close */
#define RS_F_CHUNKED   0x04   /* Transfer-Encoding: chunked body */
#define RS_F_100       0x08   /* send an unsolicited "HTTP/1.1 100 Continue" first */
#define RS_F_RAWSTATUS 0x10   /* 'reason' is the whole status line (without CRLF) */
#define RS_F_HTTP10    0x20   /* HTTP/1.0 status line */
#define RS_F_BIGBODY   0x40   /* body = 'code2' pattern bytes instead of 'body' */
#define RS_F_NOBODYLEN 0x80   /* never send a Content-Length (for 1xx/204/304 style replies) */
#define RS_F_COND304   0x100  /* request with If-None-Match / If-Modified-Since -> 304 with the same headers, no body */

typedef struct {
    const char *path;     /* exact request-target, or prefix when it ends in '*' */
    int code;
    const char *hdrs;     /* header lines, each ending in \r\n, %-expanded; NULL = none */
    const char *body;     /* NULL = "" */
    unsigned flags;
    const char *reason;   /* NULL = standard reason phrase */
    int code2;            /* RS_F_BIGBODY: body size */
    const char *pre;      /* raw bytes sent before the status line (e.g. interim 1xx responses), %-expanded */
} rs_route;

#define RS_MAXR 48
typedef struct {
    rs_route r[RS_MAXR]; int n;
    unsigned short alt_port;
    char tok[64];
    volatile LONG hits;
    srv *s;
} rs_router;

void rs_router_init(rs_router *r);
void rs_add(rs_router *r, const char *path, int code, const char *hdrs, const char *body);
rs_route *rs_addx(rs_router *r, const char *path, int code, const char *hdrs, const char *body, unsigned flags);
/* Start a router server (SRV_HTTP or SRV_HTTPS). NULL on failure (srv_last_error()). */
srv *rs_start(rs_router *r, srv_kind kind);
const char *rs_reason(int code);

/* Status callback recorder (A or W). The callback is installed on the session handle. */
#define RS_MAXCB 256
typedef struct {
    int n;
    DWORD st[RS_MAXCB];
    DWORD len[RS_MAXCB];
    DWORD dw[RS_MAXCB];           /* first DWORD of the info when len >= 4 */
    char str[RS_MAXCB][300];      /* REDIRECT / RESOLVING_NAME etc. strings (W converted to ACP) */
    DWORD_PTR ctx[RS_MAXCB];
    int wide;
} rs_cb;
extern rs_cb g_rs_cb;
void rs_cb_install(HINTERNET hi, int wide);
int  rs_cb_count(DWORD status);
int  rs_cb_index(DWORD status, int nth);   /* index of the nth occurrence (0-based), -1 */
void rs_cb_dump(void);

/* One request through InternetConnect/HttpOpenRequest/HttpSendRequest */
typedef struct {
    BOOL ok; DWORD err;
    DWORD status; char text[256]; char version[32];
    char url[1024];         /* INTERNET_OPTION_URL after the send */
    char location[1024];    /* HTTP_QUERY_LOCATION ("" when absent) */
    DWORD loc_err;
    char body[8192]; size_t nbody; int read_ok;
    char raw[4096];         /* RAW_HEADERS_CRLF */
} rs_res;

typedef struct {
    const char *agent;          /* default "rs-agent/1.0" */
    const char *host;           /* InternetConnect host, default 127.0.0.1 */
    DWORD flags;                /* HttpOpenRequest flags (SECURE added for https servers) */
    const char *hdrs;           /* HttpSendRequest headers */
    const void *data; DWORD ndata;
    const char *referrer;
    DWORD secflags;             /* OR'ed into INTERNET_OPTION_SECURITY_FLAGS before send (https) */
    int cb;                     /* 1 = install A status callback, 2 = W */
    int keep_open;              /* leave handles open (out_hreq gets the request handle, caller closes hi) */
    int no_read;                /* do not read the body */
    HINTERNET *out_hi, *out_hreq;
} rs_opt;

/* method may be NULL (GET). Returns ok (HttpSendRequest result). */
BOOL rs_do(srv *s, const char *method, const char *path, const rs_opt *o, rs_res *res);
/* Fill status/text/url/location/body/raw for an already-sent request handle. */
void rs_collect(HINTERNET hr, rs_res *res, int read_body);
DWORD rs_status(HINTERNET hr);
const char *rs_err(DWORD e);

#define RS_START(rt, kind, sv) do { (sv) = rs_start((rt), (kind)); if (!(sv)) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; } } while (0)
#define RS_FRESH  T_INET_FRESH
#define RS_NOREDIR T_INET_FRESH_NOREDIR
/* cookies allowed (no NO_COOKIES), cache neither read nor written */
#define RS_FRESH_COOKIES (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_UI)

/* built-in "200 hello" keep-alive server with a 1 s idle timeout (fast srv_stop) */
srv *rs_plain(void);
/* "127.0.0.1:<port>" of a server */
const char *rs_hp(srv *s);
/* number of requests the server recorded after waiting up to ms for at least 'want' */
int rs_wait(srv *s, int want, DWORD ms);
#endif
