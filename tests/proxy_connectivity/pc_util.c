/* pc_util.c - helpers for proxy_connectivity (see pc.h). Scaffolding only: no TESTs here. */
#include "pc.h"
#include <stdlib.h>

static pc_ws_t g_ws; static int g_ws_state;   /* 0 unknown, 1 ok, -1 missing */
const pc_ws_t *pc_ws(void) {
    if (g_ws_state == 0) {
#define L(f) g_ws.f##_ = UIN("ws2_32.dll", f); if (!g_ws.f##_) { g_ws_state = -1; return NULL; }
        L(WSAStartup) L(socket) L(bind) L(listen) L(accept) L(connect) L(send) L(recv) L(closesocket) L(shutdown)
        L(select) L(setsockopt) L(getsockname)
#undef L
        WSADATA wd; g_ws.WSAStartup_(MAKEWORD(2, 2), &wd);
        g_ws_state = 1;
    }
    return g_ws_state > 0 ? &g_ws : NULL;
}

static unsigned short be16(unsigned short v) { return (unsigned short)((v >> 8) | (v << 8)); }

unsigned short pc_closed_port(void) {
    const pc_ws_t *w = pc_ws(); if (!w) return 0;
    SOCKET s = w->socket_(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (s == INVALID_SOCKET) return 0;
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = 0x0100007f;
    int al = sizeof a; unsigned short port = 0;
    if (!w->bind_(s, (struct sockaddr *)&a, sizeof a) && !w->getsockname_(s, (struct sockaddr *)&a, &al)) port = be16(a.sin_port);
    w->closesocket_(s);
    return port;
}

void pc_set_timeouts(HINTERNET h, DWORD c, DWORD s, DWORD r) {
    if (c) U(InternetSetOptionA)(h, INTERNET_OPTION_CONNECT_TIMEOUT, &c, sizeof c);
    if (s) U(InternetSetOptionA)(h, INTERNET_OPTION_SEND_TIMEOUT, &s, sizeof s);
    if (r) U(InternetSetOptionA)(h, INTERNET_OPTION_RECEIVE_TIMEOUT, &r, sizeof r);
}

HINTERNET pc_open(const char *agent, DWORD access, const char *proxy, const char *bypass, DWORD to) {
    t_net_prepare();
    if (!U(InternetOpenA)) return NULL;
    HINTERNET h = U(InternetOpenA)(agent ? agent : "pc_agent", access, proxy, bypass, 0);
    if (h && to) pc_set_timeouts(h, to, to, to);
    return h;
}
HINTERNET pc_open_proxy(const char *proxy, const char *bypass) { return pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, proxy, bypass, 5000); }

int pc_request(HINTERNET session, const char *host, INTERNET_PORT port, const char *path, const pc_req_opt *o, DWORD *err) {
    static const pc_req_opt dflt;
    if (!o) o = &dflt;
    if (err) *err = 0;
    if (o->body && o->cap) o->body[0] = 0;
    DWORD flags = o->flags ? o->flags : T_INET_FRESH;
    if (o->secure) flags |= INTERNET_FLAG_SECURE;
    HINTERNET hc = U(InternetConnectA)(session, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hc) { if (err) *err = GetLastError(); return 0; }
    HINTERNET hr = U(HttpOpenRequestA)(hc, o->verb ? o->verb : "GET", path, NULL, NULL, NULL, flags, 0);
    if (!hr) { if (err) *err = GetLastError(); U(InternetCloseHandle)(hc); return 0; }
    if (o->proxy_user) U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_USERNAME, (void *)o->proxy_user, (DWORD)strlen(o->proxy_user) + 1);
    if (o->proxy_pass) U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_PASSWORD, (void *)o->proxy_pass, (DWORD)strlen(o->proxy_pass) + 1);
    if (o->secflags) t_https_secflags(hr, o->secflags);
    DWORD t0 = GetTickCount();
    BOOL ok = U(HttpSendRequestA)(hr, o->headers, o->headers ? (DWORD)-1 : 0, NULL, 0);
    DWORD e = ok ? 0 : GetLastError();
    int st = 0;
    if (ok) {
        DWORD v = 0, l = sizeof v;
        if (U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &v, &l, NULL)) st = (int)v;
        if (st == 407 && o->resend_on_407) {
            char sink[512]; DWORD rd; for (int g = 0; g < 64 && U(InternetReadFile)(hr, sink, sizeof sink, &rd) && rd; g++) {}
            ok = U(HttpSendRequestA)(hr, o->headers, o->headers ? (DWORD)-1 : 0, NULL, 0);
            e = ok ? 0 : GetLastError(); st = 0;
            if (ok) { v = 0; l = sizeof v; if (U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &v, &l, NULL)) st = (int)v; }
        }
        if (ok) { char tmp[1]; t_inet_read_all(hr, o->body && o->cap ? o->body : tmp, o->body && o->cap ? o->cap : 1, NULL); }
    }
    if (o->ms) *o->ms = GetTickCount() - t0;
    if (err) *err = e;
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc);
    return st;
}

int pc_get(HINTERNET session, const char *url, DWORD flags, char *body, size_t cap, DWORD *err, DWORD *ms) {
    DWORD t0 = GetTickCount(); size_t n;
    int st = t_http_get(session, url, NULL, flags ? flags : T_INET_FRESH, body, cap, &n, err);
    if (ms) *ms = GetTickCount() - t0;
    return st;
}

int pc_bounded(DWORD (WINAPI *fn)(void *), void *arg, DWORD ms) {
    HANDLE th = CreateThread(NULL, 0, fn, arg, 0, NULL);
    if (!th) { fn(arg); return 1; }
    DWORD w = WaitForSingleObject(th, ms);
    CloseHandle(th);
    return w == WAIT_OBJECT_0;
}

/* ------------------------------------------------------------------ CONNECT relay */
#define RELAY_MAXH 8
struct pc_relay {
    SOCKET ls; unsigned short port, tport; HANDLE thr, stop;
    const char *const *replies; int nreplies;
    CRITICAL_SECTION cs; char *heads[RELAY_MAXH]; volatile LONG nheads, nconns, tbytes;
};

static int relay_sendall(SOCKET s, const char *p, int n) {
    const pc_ws_t *w = pc_ws();
    while (n > 0) { int r = w->send_(s, p, n, 0); if (r <= 0) return -1; p += r; n -= r; }
    return 0;
}
static int fd_has(const fd_set *s, SOCKET x) { for (u_int i = 0; i < s->fd_count; i++) if (s->fd_array[i] == x) return 1; return 0; }
static int relay_readable(SOCKET a, SOCKET b, DWORD ms, int *ra, int *rb) {
    const pc_ws_t *w = pc_ws(); fd_set rs; FD_ZERO(&rs); FD_SET(a, &rs); if (b != INVALID_SOCKET) FD_SET(b, &rs);
    struct timeval tv = { (long)(ms / 1000), (long)((ms % 1000) * 1000) };
    int r = w->select_(0, &rs, NULL, NULL, &tv);
    *ra = r > 0 && fd_has(&rs, a); if (rb) *rb = r > 0 && b != INVALID_SOCKET && fd_has(&rs, b);
    return r;
}
static void relay_tunnel(pc_relay *r, SOCKET c, const char *pending, int npending) {
    const pc_ws_t *w = pc_ws();
    SOCKET t = w->socket_(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (t == INVALID_SOCKET) return;
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = be16(r->tport); a.sin_addr.s_addr = 0x0100007f;
    if (w->connect_(t, (struct sockaddr *)&a, sizeof a)) { w->closesocket_(t); return; }
    if (npending > 0) { relay_sendall(t, pending, npending); InterlockedExchangeAdd(&r->tbytes, npending); }
    char buf[16384]; DWORD start = GetTickCount();
    while (GetTickCount() - start < 15000 && WaitForSingleObject(r->stop, 0) != WAIT_OBJECT_0) {
        int rc, rt; if (relay_readable(c, t, 200, &rc, &rt) < 0) break;
        if (rc) { int n = w->recv_(c, buf, sizeof buf, 0); if (n <= 0) break; InterlockedExchangeAdd(&r->tbytes, n); if (relay_sendall(t, buf, n)) break; }
        if (rt) { int n = w->recv_(t, buf, sizeof buf, 0); if (n <= 0) break; if (relay_sendall(c, buf, n)) break; }
    }
    w->shutdown_(t, SD_BOTH); w->closesocket_(t);
}
static void relay_conn(pc_relay *r, SOCKET c) {
    const pc_ws_t *w = pc_ws();
    char in[16384]; int nin = 0; DWORD start = GetTickCount();
    while (GetTickCount() - start < 15000 && WaitForSingleObject(r->stop, 0) != WAIT_OBJECT_0) {
        char *end = NULL;
        for (int i = 0; i + 3 < nin; i++) if (!memcmp(in + i, "\r\n\r\n", 4)) { end = in + i + 4; break; }
        if (!end) {
            if (nin >= (int)sizeof in - 1) break;
            int rc; if (relay_readable(c, INVALID_SOCKET, 200, &rc, NULL) < 0) break;
            if (!rc) continue;
            int n = w->recv_(c, in + nin, (int)sizeof in - 1 - nin, 0); if (n <= 0) break;
            nin += n; continue;
        }
        int hl = (int)(end - in); int idx = -1;
        EnterCriticalSection(&r->cs);
        if (r->nheads < RELAY_MAXH) { idx = r->nheads; r->heads[idx] = malloc(hl + 1); memcpy(r->heads[idx], in, hl); r->heads[idx][hl] = 0; r->nheads++; }
        LeaveCriticalSection(&r->cs);
        int ri = idx < 0 ? r->nreplies - 1 : (idx < r->nreplies ? idx : r->nreplies - 1);
        const char *rep = r->replies[ri];
        /* a request body announced with Content-Length: swallow it (bounded) */
        memmove(in, end, nin - hl); nin -= hl;
        if (relay_sendall(c, rep, (int)strlen(rep))) break;
        if (!strncmp(rep, "HTTP/1.1 200", 12) || !strncmp(rep, "HTTP/1.0 200", 12)) {
            if (r->tport) relay_tunnel(r, c, in, nin);
            break;
        }
        if (strstr(rep, "Connection: close") || strstr(rep, "connection: close")) break;
    }
    w->shutdown_(c, SD_BOTH); w->closesocket_(c);
}
static DWORD WINAPI relay_main(void *p) {
    pc_relay *r = p; const pc_ws_t *w = pc_ws();
    DWORD start = GetTickCount();
    while (GetTickCount() - start < 30000 && WaitForSingleObject(r->stop, 0) != WAIT_OBJECT_0 && r->nconns < 4) {
        int rl; if (relay_readable(r->ls, INVALID_SOCKET, 100, &rl, NULL) < 0) break;
        if (!rl) continue;
        SOCKET c = w->accept_(r->ls, NULL, NULL); if (c == INVALID_SOCKET) break;
        InterlockedIncrement(&r->nconns);
        relay_conn(r, c);
    }
    return 0;
}
pc_relay *pc_relay_start(const char *const *replies, int nreplies, unsigned short tport) {
    const pc_ws_t *w = pc_ws(); if (!w || nreplies < 1) return NULL;
    pc_relay *r = calloc(1, sizeof *r);
    r->replies = replies; r->nreplies = nreplies; r->tport = tport;
    InitializeCriticalSection(&r->cs);
    r->ls = w->socket_(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = 0x0100007f; int al = sizeof a;
    if (r->ls == INVALID_SOCKET || w->bind_(r->ls, (struct sockaddr *)&a, sizeof a) || w->listen_(r->ls, 8) ||
        w->getsockname_(r->ls, (struct sockaddr *)&a, &al)) { if (r->ls != INVALID_SOCKET) w->closesocket_(r->ls); free(r); return NULL; }
    r->port = be16(a.sin_port);
    r->stop = CreateEventA(NULL, TRUE, FALSE, NULL);
    r->thr = CreateThread(NULL, 0, relay_main, r, 0, NULL);
    return r;
}
unsigned short pc_relay_port(pc_relay *r) { return r->port; }
int pc_relay_heads(pc_relay *r) { return (int)r->nheads; }
int pc_relay_conns(pc_relay *r) { return (int)r->nconns; }
long pc_relay_tunnel_bytes(pc_relay *r) { return r->tbytes; }
const char *pc_relay_head(pc_relay *r, int i) { return i >= 0 && i < r->nheads ? r->heads[i] : NULL; }
int pc_relay_wait_heads(pc_relay *r, int n, DWORD ms) {
    DWORD t0 = GetTickCount();
    while (r->nheads < n) { if (GetTickCount() - t0 > ms) return 0; Sleep(10); }
    return 1;
}
void pc_relay_stop(pc_relay *r) {
    if (!r) return;
    SetEvent(r->stop);
    if (WaitForSingleObject(r->thr, 20000) != WAIT_OBJECT_0) { t_note("relay: thread leak"); return; }
    CloseHandle(r->thr); CloseHandle(r->stop); pc_ws()->closesocket_(r->ls);
    for (int i = 0; i < r->nheads; i++) free(r->heads[i]);
    DeleteCriticalSection(&r->cs); free(r);
}

static char g_rot[8][1024]; static volatile LONG g_roti;
static char *rot(void) { return g_rot[InterlockedIncrement(&g_roti) & 7]; }
const char *pc_head_line(const char *head) {
    if (!head) return NULL;
    char *o = rot(); const char *e = strstr(head, "\r\n"); size_t n = e ? (size_t)(e - head) : strlen(head);
    if (n > 1023) n = 1023; memcpy(o, head, n); o[n] = 0; return o;
}
const char *pc_head_header(const char *head, const char *name) {
    if (!head) return NULL;
    size_t nl = strlen(name);
    for (const char *p = strstr(head, "\r\n"); p && p[2] && !(p[2] == '\r' && p[3] == '\n'); p = strstr(p + 2, "\r\n")) {
        const char *ln = p + 2;
        if (!_strnicmp(ln, name, nl) && ln[nl] == ':') {
            const char *v = ln + nl + 1; while (*v == ' ' || *v == '\t') v++;
            const char *e = strstr(v, "\r\n"); size_t n = e ? (size_t)(e - v) : strlen(v);
            while (n && (v[n - 1] == ' ' || v[n - 1] == '\t')) n--;
            char *o = rot(); if (n > 1023) n = 1023; memcpy(o, v, n); o[n] = 0; return o;
        }
    }
    return NULL;
}

void pc_note_req(srv *s, int i) {
    t_note("req %d: %s", i, srv_req_line(s, i) ? srv_req_line(s, i) : "(none)");
    int n = srv_req_header_count(s, i);
    for (int h = 0; h < n; h++) t_note("  hdr[%d] %s: %s", h, srv_req_header_name(s, i, h), srv_req_header_value(s, i, h));
}
