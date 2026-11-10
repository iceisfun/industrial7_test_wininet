/* pc.h - shared helpers for the proxy_connectivity area (prefix pc_).
 * No internet: every proxy, origin and tunnel endpoint is a loopback server started by the test.
 * Names that must never resolve use the reserved .invalid TLD (the lab guest has no DNS at all, 04 F5). */
#ifndef PC_H
#define PC_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

/* common/t.h's EXPECT_EQ/EXPECT_NE evaluate their first argument twice (comparison + "got" value). Here that sent every
 * EXPECT_EQ(pc_get(...), 200) request twice (found in Win10 boot 5). Single-evaluation versions for this area: */
#undef EXPECT_EQ
#undef EXPECT_NE
#define EXPECT_EQ(a, b) do { ULONG_PTR pa_ = (ULONG_PTR)(a), pb_ = (ULONG_PTR)(b); \
    t_check(pa_ == pb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", (unsigned long long)pa_, (unsigned long long)pb_); } while (0)
#define EXPECT_NE(a, b) do { ULONG_PTR pa_ = (ULONG_PTR)(a), pb_ = (ULONG_PTR)(b); \
    t_check(pa_ != pb_, __FILE__, __LINE__, #a " != " #b, "got 0x%llx", (unsigned long long)pa_); } while (0)

#define START_OR_SKIP(cfgp, sp) do { int rc_ = srv_start((cfgp), (sp)); if (rc_) { t_skip("server unavailable: %s", srv_strerror(rc_)); return; } } while (0)
#define HTTP_OR_SKIP(var, steps) srv *var = srv_http((steps), (int)(sizeof(steps) / sizeof((steps)[0]))); \
    if (!var) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }

#ifndef ERROR_INTERNET_PROXY_SERVER_UNREACHABLE
#define ERROR_INTERNET_PROXY_SERVER_UNREACHABLE 12165
#endif
#ifndef ERROR_INTERNET_AUTODETECTION_FAILED
#define ERROR_INTERNET_AUTODETECTION_FAILED 12180
#endif
#ifndef ERROR_INTERNET_SEC_INVALID_CERT
#define ERROR_INTERNET_SEC_INVALID_CERT 12169
#endif
#ifndef INTERNET_OPTION_PER_CONNECTION_OPTION
#define INTERNET_OPTION_PER_CONNECTION_OPTION 75
#endif

/* Win10 WININET_PROXY_INFO / _LIST (not in mingw headers). x64: 0x20 per entry (InternetFreeProxyInfoList stride). */
typedef struct { BOOL fProxy; BOOL fBypass; INTERNET_SCHEME ProxyScheme; PWSTR pwszProxy; INTERNET_PORT ProxyPort; } PC_PROXY_INFO;
typedef struct { DWORD dwProxyInfoCount; PC_PROXY_INFO *pProxyInfo; } PC_PROXY_INFO_LIST;

/* ws2_32 via GetProcAddress (nothing is import-linked) */
typedef struct {
    __typeof__(&WSAStartup) WSAStartup_; __typeof__(&socket) socket_; __typeof__(&bind) bind_; __typeof__(&listen) listen_;
    __typeof__(&accept) accept_; __typeof__(&connect) connect_; __typeof__(&send) send_; __typeof__(&recv) recv_;
    __typeof__(&closesocket) closesocket_; __typeof__(&shutdown) shutdown_; __typeof__(&select) select_;
    __typeof__(&setsockopt) setsockopt_; __typeof__(&getsockname) getsockname_;
} pc_ws_t;
const pc_ws_t *pc_ws(void);                /* NULL if any export is missing */

unsigned short pc_closed_port(void);       /* a loopback port with no listener (bound once, then closed); 0 on failure */

/* sessions */
HINTERNET pc_open(const char *agent, DWORD access, const char *proxy, const char *bypass, DWORD timeout_ms);
HINTERNET pc_open_proxy(const char *proxy, const char *bypass);   /* PROXY session, 5 s timeouts */
void pc_set_timeouts(HINTERNET h, DWORD connect_ms, DWORD send_ms, DWORD recv_ms);

/* One HttpOpenRequest round trip on an existing session. Returns status (0 on failure, *err = GetLastError). */
typedef struct {
    const char *verb;          /* default GET */
    const char *headers;       /* extra request headers or NULL */
    DWORD flags;               /* default T_INET_FRESH */
    const char *proxy_user, *proxy_pass;   /* INTERNET_OPTION_PROXY_USERNAME/PASSWORD on the request handle */
    DWORD secflags;            /* OR'ed into SECURITY_FLAGS before send (HTTPS) */
    int secure;                /* INTERNET_FLAG_SECURE */
    int resend_on_407;         /* re-send the same handle once when the first response is 407 */
    char *body; size_t cap;    /* optional body sink */
    DWORD *ms;                 /* optional elapsed time of HttpSendRequest */
} pc_req_opt;
int pc_request(HINTERNET session, const char *host, INTERNET_PORT port, const char *path, const pc_req_opt *o, DWORD *err);
/* InternetOpenUrlA wrapper: status (0 on failure), body, elapsed ms */
int pc_get(HINTERNET session, const char *url, DWORD flags, char *body, size_t cap, DWORD *err, DWORD *ms);

/* Run fn(arg) on a worker thread and wait at most ms. 1 = finished. On timeout the thread is left running (never
 * terminated) and the test should t_skip with the reason. */
int pc_bounded(DWORD (WINAPI *fn)(void *), void *arg, DWORD ms);

/* CONNECT relay proxy (raw winsock, one thread): reads request heads; replies[i] answers head i (cycling on the
 * last); a reply starting "HTTP/1.1 200" or "HTTP/1.0 200" switches the connection into a byte tunnel to
 * 127.0.0.1:tunnel_port (0 = close instead). Up to 8 heads and 4 connections are recorded. */
typedef struct pc_relay pc_relay;
pc_relay *pc_relay_start(const char *const *replies, int nreplies, unsigned short tunnel_port);
unsigned short pc_relay_port(pc_relay *r);
int  pc_relay_heads(pc_relay *r);                    /* heads recorded so far */
const char *pc_relay_head(pc_relay *r, int i);       /* raw head text (CRLFs kept), NULL if absent */
int  pc_relay_conns(pc_relay *r);
long pc_relay_tunnel_bytes(pc_relay *r);             /* client->target bytes relayed */
int  pc_relay_wait_heads(pc_relay *r, int n, DWORD ms);
void pc_relay_stop(pc_relay *r);
/* header value (case-insensitive) from a raw head; returns static rotating buffer or NULL */
const char *pc_head_header(const char *head, const char *name);
const char *pc_head_line(const char *head);          /* first line, rotating buffer */

void pc_note_req(srv *s, int i);                     /* t_note the request line and every header of request i */
#endif
