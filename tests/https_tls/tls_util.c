/* tls_util.c - helpers for the https_tls area: request bundle, HTTPS server wrappers, raw ClientHello observer,
 * VM_TIMEOUT: 300
 * CONNECT tunnel proxy. ws2_32 is resolved at run time (UIN), nothing is import-linked. */
#include "tls_util.h"

/* ------------------------------------------------------------------ winsock (runtime) */
static struct {
    int ok;
    __typeof__(&WSAStartup) WSAStartup_;
    __typeof__(&socket) socket_; __typeof__(&bind) bind_; __typeof__(&listen) listen_; __typeof__(&accept) accept_;
    __typeof__(&connect) connect_; __typeof__(&send) send_; __typeof__(&recv) recv_; __typeof__(&closesocket) close_;
    __typeof__(&setsockopt) sso_; __typeof__(&getsockname) gsn_; __typeof__(&select) select_; __typeof__(&shutdown) shutdown_;
} W;
static INIT_ONCE g_ws_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK ws_init(PINIT_ONCE o, PVOID p, PVOID *c) {
    W.WSAStartup_ = UIN("ws2_32.dll", WSAStartup);
    W.socket_ = UIN("ws2_32.dll", socket); W.bind_ = UIN("ws2_32.dll", bind); W.listen_ = UIN("ws2_32.dll", listen);
    W.accept_ = UIN("ws2_32.dll", accept); W.connect_ = UIN("ws2_32.dll", connect); W.send_ = UIN("ws2_32.dll", send);
    W.recv_ = UIN("ws2_32.dll", recv); W.close_ = UIN("ws2_32.dll", closesocket); W.sso_ = UIN("ws2_32.dll", setsockopt);
    W.gsn_ = UIN("ws2_32.dll", getsockname); W.select_ = UIN("ws2_32.dll", select); W.shutdown_ = UIN("ws2_32.dll", shutdown);
    if (W.WSAStartup_ && W.socket_ && W.bind_ && W.listen_ && W.accept_ && W.connect_ && W.send_ && W.recv_ && W.close_ &&
        W.sso_ && W.gsn_ && W.select_ && W.shutdown_) {
        WSADATA wd; W.ok = W.WSAStartup_(MAKEWORD(2, 2), &wd) == 0;
    }
    return TRUE;
}
int tls_ws_ok(void) { InitOnceExecuteOnce(&g_ws_once, ws_init, NULL, NULL); return W.ok; }

static SOCKET listen_loopback(unsigned short *port) {
    SOCKET s = W.socket_(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return s;
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = 0x0100007fu;
    int al = sizeof a;
    if (W.bind_(s, (struct sockaddr *)&a, sizeof a) || W.listen_(s, 8) || W.gsn_(s, (struct sockaddr *)&a, &al)) { W.close_(s); return INVALID_SOCKET; }
    *port = (unsigned short)((a.sin_port >> 8) | (a.sin_port << 8));
    return s;
}
static void set_timeouts(SOCKET s, DWORD ms) {
    W.sso_(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, sizeof ms);
    W.sso_(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&ms, sizeof ms);
}
static void hard_reset(SOCKET s) {
    struct linger lg = { 1, 0 }; W.sso_(s, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg); W.close_(s);
}
/* accept with a bounded wait; INVALID_SOCKET on timeout/stop */
static SOCKET accept_bounded(SOCKET ls, HANDLE stop, DWORD total_ms) {
    DWORD t0 = GetTickCount();
    while (GetTickCount() - t0 < total_ms) {
        if (WaitForSingleObject(stop, 0) == WAIT_OBJECT_0) return INVALID_SOCKET;
        fd_set fs; FD_ZERO(&fs); FD_SET(ls, &fs);
        struct timeval tv = { 0, 100000 };
        int r = W.select_(0, &fs, NULL, NULL, &tv);
        if (r > 0) return W.accept_(ls, NULL, NULL);
        if (r < 0) return INVALID_SOCKET;
    }
    return INVALID_SOCKET;
}

const char *tls_hostport(const char *host, unsigned short port) {
    static char b[8][128]; static LONG n;
    char *o = b[InterlockedIncrement(&n) & 7];
    snprintf(o, 128, "%s:%u", host, port);
    return o;
}

/* ------------------------------------------------------------------ wininet request bundle */
int treq_open(treq *t, const char *host, unsigned short port, const char *verb, const char *path, DWORD flags) {
    memset(t, 0, sizeof *t);
    t->hi = t_inet_open("tls-test");
    if (!t->hi) return 0;
    t->hc = U(InternetConnectA)(t->hi, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!t->hc) return 0;
    t->hr = U(HttpOpenRequestA)(t->hc, verb ? verb : "GET", path ? path : "/", NULL, NULL, NULL, flags, 0);
    return t->hr != NULL;
}
int treq_open_proxy(treq *t, const char *proxy, const char *host, unsigned short port, const char *path, DWORD flags) {
    memset(t, 0, sizeof *t);
    t->hi = U(InternetOpenA)("tls-test", INTERNET_OPEN_TYPE_PROXY, proxy, NULL, 0);
    if (!t->hi) return 0;
    DWORD to = 5000;
    U(InternetSetOptionA)(t->hi, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
    U(InternetSetOptionA)(t->hi, INTERNET_OPTION_SEND_TIMEOUT, &to, sizeof to);
    U(InternetSetOptionA)(t->hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
    t->hc = U(InternetConnectA)(t->hi, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!t->hc) return 0;
    t->hr = U(HttpOpenRequestA)(t->hc, "GET", path ? path : "/", NULL, NULL, NULL, flags, 0);
    return t->hr != NULL;
}
void treq_close(treq *t) {
    if (t->hr) U(InternetCloseHandle)(t->hr);
    if (t->hc) U(InternetCloseHandle)(t->hc);
    if (t->hi) U(InternetCloseHandle)(t->hi);
    memset(t, 0, sizeof *t);
}
DWORD treq_send(treq *t) {
    SetLastError(0xDEAD);
    BOOL ok = U(HttpSendRequestA)(t->hr, NULL, 0, NULL, 0);
    return ok ? 0 : GetLastError();
}
DWORD treq_status(treq *t) {
    DWORD st = 0, l = sizeof st;
    if (!U(HttpQueryInfoA)(t->hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL)) return 0;
    return st;
}
BOOL tls_send_retry(HINTERNET hr, const char *hdr, DWORD hl, void *opt, DWORD ol) {
    SetLastError(0xDEAD);
    BOOL ok = U(HttpSendRequestA)(hr, hdr, hl, opt, ol);
    DWORD e = ok ? 0 : GetLastError();
    if (e == ERROR_INTERNET_CONNECTION_RESET) {
        t_note("transient %lu on send, retrying once", e);
        SetLastError(0xDEAD);
        ok = U(HttpSendRequestA)(hr, hdr, hl, opt, ol);
    }
    return ok;
}
size_t treq_body(treq *t, char *buf, size_t cap) { return t_inet_read_all(t->hr, buf, cap, NULL); }
DWORD tls_secflags(HINTERNET h) {
    DWORD f = 0, l = sizeof f;
    if (!U(InternetQueryOptionA)(h, INTERNET_OPTION_SECURITY_FLAGS, &f, &l)) return 0xDEADBEEF;
    return f;
}
int tls_set_secflags(HINTERNET h, DWORD v) { return U(InternetSetOptionA)(h, INTERNET_OPTION_SECURITY_FLAGS, &v, sizeof v); }

DWORD tls_try(srv *s, const char *host, DWORD secflags, DWORD openflags, DWORD *status) {
    treq t; DWORD err;
    *status = 0;
    if (!treq_open(&t, host ? host : "127.0.0.1", srv_port(s), "GET", "/x", T_INET_FRESH | INTERNET_FLAG_SECURE | openflags)) { err = GetLastError(); treq_close(&t); return err ? err : 1; }
    if (secflags) t_https_secflags(t.hr, secflags);
    err = treq_send(&t);
    /* a fresh loopback TLS connection aborts transiently about once per boot (VM, several areas): retry once, noted */
    if (err == ERROR_INTERNET_CONNECTION_RESET) { t_note("transient %lu on send, retrying once", err); err = treq_send(&t); }
    if (!err) { char b[64]; *status = treq_status(&t); treq_body(&t, b, sizeof b); }
    treq_close(&t);
    return err;
}

/* ------------------------------------------------------------------ HTTPS server wrappers */
srv *tls_srv(int profile, const srv_step *st, int nsteps) { return srv_https(st, nsteps, profile); }
srv *tls_srv_cfg(int profile, DWORD protocols, int client_cert, const srv_step *st, int nsteps, int *rc) {
    static srv_script sc[64]; static LONG n;   /* scripts must outlive the server: rotating static slots */
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTPS; cfg.cert_profile = profile; cfg.tls_protocols = protocols; cfg.tls_client_cert = client_cert;
    if (st) { srv_script *p = &sc[InterlockedIncrement(&n) & 63]; p->steps = st; p->nsteps = nsteps; cfg.scripts = p; cfg.nscripts = 1; }
    srv *s = NULL; int r = srv_start(&cfg, &s);
    if (rc) *rc = r;
    return r == SRV_OK ? s : NULL;
}
const char *tls_done_data(srv *s, int idx) {
    const srv_event *ev; int ne = srv_events(s, &ev), k = 0;
    for (int i = 0; i < ne; i++) if (ev[i].kind == SRV_EV_TLS_DONE) { if (k == idx) return ev[i].data; k++; }
    return NULL;
}
int tls_count(srv *s, srv_ev_kind k) { return srv_count_events(s, k); }
void tls_dump_tls_events(srv *s) {
    const srv_event *ev; int ne = srv_events(s, &ev);
    for (int i = 0; i < ne; i++)
        if (ev[i].kind == SRV_EV_TLS_DONE || ev[i].kind == SRV_EV_TLS_ABORT || ev[i].kind == SRV_EV_ERROR)
            t_note("srv ev conn=%d %s %s", ev[i].conn, srv_event_kind_name(ev[i].kind), ev[i].data ? ev[i].data : "");
}
DWORD tls_ev_field(const char *data, const char *key) {
    if (!data) return 0xFFFFFFFF;
    char k[32]; snprintf(k, sizeof k, "%s=", key);
    const char *p = strstr(data, k);
    if (!p) return 0xFFFFFFFF;
    return (DWORD)strtoul(p + strlen(k), NULL, 0);
}

/* ------------------------------------------------------------------ ClientHello observer */
struct th_srv {
    SOCKET ls; unsigned short port; int reaction;
    HANDLE thr, stop; CRITICAL_SECTION cs;
    int nconn; th_hello h[TH_MAX_CONN];
};
static unsigned g16(const unsigned char *p) { return (p[0] << 8) | p[1]; }
static void parse_hello(th_hello *h, const unsigned char *b, size_t n) {
    h->nbytes = n;
    if (n < 5) return;
    h->rec_type = b[0]; h->rec_ver = g16(b + 1);
    /* concatenate handshake fragments of consecutive handshake records */
    static __thread unsigned char hs[65536]; size_t hn = 0, off = 0;
    while (off + 5 <= n && b[off] == 0x16) {
        size_t rl = g16(b + off + 3);
        if (off + 5 + rl > n) { size_t avail = n - off - 5; memcpy(hs + hn, b + off + 5, avail); hn += avail; break; }
        if (hn + rl > sizeof hs) break;
        memcpy(hs + hn, b + off + 5, rl); hn += rl; off += 5 + rl;
        if (hn >= 4 && hn >= 4 + (size_t)((hs[1] << 16) | (hs[2] << 8) | hs[3])) break;
    }
    if (hn < 4) return;
    h->hs_type = hs[0];
    size_t ml = (hs[1] << 16) | (hs[2] << 8) | hs[3];
    if (hn < 4 + ml) return;
    const unsigned char *p = hs + 4, *e = hs + 4 + ml;
    if (e - p < 34) return;
    h->client_ver = g16(p); p += 34;
    if (p >= e) return; p += 1 + p[0];                     /* session id */
    if (e - p < 2) return; size_t cl = g16(p); p += 2;
    for (size_t i = 0; i + 1 < cl && h->ncipher < 128; i += 2) h->ciphers[h->ncipher++] = (unsigned short)g16(p + i);
    p += cl;
    if (p >= e) return; p += 1 + p[0];                     /* compression */
    if (e - p < 2) { h->complete = 1; return; }
    size_t el = g16(p); p += 2;
    const unsigned char *xe = p + el; if (xe > e) xe = e;
    while (xe - p >= 4) {
        unsigned t = g16(p), l = g16(p + 2); const unsigned char *d = p + 4;
        if (d + l > xe) break;
        if (h->nexts < 64) h->exts[h->nexts++] = (unsigned short)t;
        if (t == 0 && l >= 5) {                             /* server_name */
            unsigned nl = g16(d + 3);
            if (d[2] == 0 && 5 + nl <= l && nl < sizeof h->sni) { memcpy(h->sni, d + 5, nl); h->sni[nl] = 0; h->has_sni = 1; }
        } else if (t == 16 && l >= 2) {                     /* ALPN */
            const unsigned char *q = d + 2, *qe = d + l; size_t o = 0;
            h->has_alpn = 1;
            while (q < qe && q + 1 + q[0] <= qe) {
                if (o && o < sizeof h->alpn - 1) h->alpn[o++] = ',';
                for (int i = 0; i < q[0] && o < sizeof h->alpn - 1; i++) h->alpn[o++] = (char)q[1 + i];
                q += 1 + q[0];
            }
            h->alpn[o] = 0;
        } else if (t == 43 && l >= 1) {                     /* supported_versions */
            for (unsigned i = 0; i + 1 < d[0] && h->nver < 16 && 1 + i + 1 < l; i += 2) h->versions[h->nver++] = (unsigned short)g16(d + 1 + i);
        } else if (t == 23) h->has_ems = 1;
        else if (t == 0xff01) h->has_reneg_info = 1;
        else if (t == 5) h->has_status_request = 1;
        else if (t == 13) h->has_sigalgs = 1;
        p = d + l;
    }
    h->complete = 1;
}
static int hello_len_known(const unsigned char *b, size_t n) {
    /* 1 when the whole ClientHello handshake message is buffered */
    if (n < 9) return 0;
    if (b[0] != 0x16) return 1;                             /* not TLS: take what we have */
    size_t ml = (b[6] << 16) | (b[7] << 8) | b[8];
    size_t have = 0, off = 0;
    while (off + 5 <= n && b[off] == 0x16) { size_t rl = g16(b + off + 3); have += (off + 5 + rl <= n) ? rl : n - off - 5; if (off + 5 + rl > n) break; off += 5 + rl; }
    return have >= 4 + ml;
}
static DWORD WINAPI th_thread(LPVOID p) {
    th_srv *t = p;
    DWORD t0 = GetTickCount();
    while (GetTickCount() - t0 < 20000) {
        SOCKET c = accept_bounded(t->ls, t->stop, 20000 - (GetTickCount() - t0));
        if (c == INVALID_SOCKET) break;
        set_timeouts(c, 3000);
        EnterCriticalSection(&t->cs); int idx = t->nconn < TH_MAX_CONN ? t->nconn : -1; LeaveCriticalSection(&t->cs);
        static __thread unsigned char buf[65536]; size_t n = 0;
        if (t->reaction != TH_SILENT_CLOSE_NOREAD) {
            while (n < sizeof buf && !hello_len_known(buf, n)) {
                int r = W.recv_(c, (char *)buf + n, (int)(sizeof buf - n), 0);
                if (r <= 0) break;
                n += r;
            }
        }
        th_hello h; memset(&h, 0, sizeof h);
        parse_hello(&h, buf, n);
        switch (t->reaction) {
        case TH_RESET: hard_reset(c); c = INVALID_SOCKET; break;
        case TH_ALERT: { static const unsigned char al[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 }; W.send_(c, (const char *)al, sizeof al, 0); Sleep(50); break; }
        case TH_PLAINTEXT_HTTP: { static const char r[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nplain"; W.send_(c, r, sizeof r - 1, 0); Sleep(50); break; }
        case TH_GARBAGE: { char g[512]; for (int i = 0; i < 512; i++) g[i] = (char)(0x41 + i % 26); W.send_(c, g, sizeof g, 0); Sleep(50); break; }
        case TH_HANGUP_AFTER_SH: {   /* a syntactically valid but truncated ServerHello record, then close */
            static const unsigned char sh[] = { 0x16, 0x03, 0x03, 0x00, 0x40, 0x02, 0x00, 0x00, 0x46, 0x03, 0x03 };
            W.send_(c, (const char *)sh, sizeof sh, 0); Sleep(50); break; }
        default: break;
        }
        if (c != INVALID_SOCKET) { W.shutdown_(c, SD_SEND); W.close_(c); }
        EnterCriticalSection(&t->cs);
        if (idx >= 0) t->h[idx] = h;
        t->nconn++;
        LeaveCriticalSection(&t->cs);
    }
    return 0;
}
th_srv *th_start(int reaction) {
    if (!tls_ws_ok()) return NULL;
    th_srv *t = calloc(1, sizeof *t);
    t->reaction = reaction;
    t->ls = listen_loopback(&t->port);
    if (t->ls == INVALID_SOCKET) { free(t); return NULL; }
    InitializeCriticalSection(&t->cs);
    t->stop = CreateEventA(NULL, TRUE, FALSE, NULL);
    t->thr = CreateThread(NULL, 0, th_thread, t, 0, NULL);
    return t;
}
unsigned short th_port(th_srv *t) { return t->port; }
int th_count(th_srv *t) { EnterCriticalSection(&t->cs); int n = t->nconn; LeaveCriticalSection(&t->cs); return n; }
int th_wait(th_srv *t, int n, DWORD ms) {
    DWORD t0 = GetTickCount();
    while (th_count(t) < n) { if (GetTickCount() - t0 > ms) return 0; Sleep(10); }
    return 1;
}
const th_hello *th_get(th_srv *t, int i) { return (i >= 0 && i < TH_MAX_CONN && i < th_count(t)) ? &t->h[i] : NULL; }
void th_stop(th_srv *t) {
    if (!t) return;
    SetEvent(t->stop);
    if (WaitForSingleObject(t->thr, 5000) != WAIT_OBJECT_0) { t_note("th: observer thread did not exit (leaked)"); return; }
    CloseHandle(t->thr); CloseHandle(t->stop); W.close_(t->ls); DeleteCriticalSection(&t->cs); free(t);
}
int th_has_ext(const th_hello *h, unsigned short type) { for (int i = 0; h && i < h->nexts; i++) if (h->exts[i] == type) return 1; return 0; }

/* ------------------------------------------------------------------ CONNECT proxy */
#define TP_MAX 8
struct tp_srv {
    SOCKET ls; unsigned short port, target; char reply[512];
    HANDLE thr, stop; CRITICAL_SECTION cs;
    int n; char head[TP_MAX][2048];
};
static int fd_has(fd_set *fs, SOCKET s) { for (u_int i = 0; i < fs->fd_count; i++) if (fs->fd_array[i] == s) return 1; return 0; }
static void relay(SOCKET a, SOCKET b, HANDLE stop) {
    char buf[16384]; DWORD t0 = GetTickCount();
    while (GetTickCount() - t0 < 15000 && WaitForSingleObject(stop, 0) != WAIT_OBJECT_0) {
        fd_set fs; FD_ZERO(&fs); FD_SET(a, &fs); FD_SET(b, &fs);
        struct timeval tv = { 0, 100000 };
        int r = W.select_(0, &fs, NULL, NULL, &tv);
        if (r < 0) return;
        if (r == 0) continue;
        SOCKET from[2] = { a, b }, to[2] = { b, a };
        for (int i = 0; i < 2; i++) if (fd_has(&fs, from[i])) {
            int k = W.recv_(from[i], buf, sizeof buf, 0);
            if (k <= 0) return;
            for (int o = 0; o < k; ) { int w = W.send_(to[i], buf + o, k - o, 0); if (w <= 0) return; o += w; }
        }
    }
}
static DWORD WINAPI tp_thread(LPVOID p) {
    tp_srv *t = p; DWORD t0 = GetTickCount();
    while (GetTickCount() - t0 < 20000) {
        SOCKET c = accept_bounded(t->ls, t->stop, 20000 - (GetTickCount() - t0));
        if (c == INVALID_SOCKET) break;
        set_timeouts(c, 5000);
        char h[2048]; int n = 0;
        while (n < (int)sizeof h - 1) {
            int r = W.recv_(c, h + n, 1, 0);   /* byte-wise: never read past the head */
            if (r <= 0) break;
            n++; h[n] = 0;
            if (n >= 4 && !memcmp(h + n - 4, "\r\n\r\n", 4)) break;
        }
        h[n] = 0;
        EnterCriticalSection(&t->cs); if (t->n < TP_MAX) strcpy(t->head[t->n], h); t->n++; LeaveCriticalSection(&t->cs);
        if (n == 0) { W.close_(c); continue; }
        W.send_(c, t->reply, (int)strlen(t->reply), 0);
        if (!strncmp(t->reply + 8, " 200", 4) && t->target) {
            SOCKET u = W.socket_(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = (unsigned short)((t->target >> 8) | (t->target << 8)); a.sin_addr.s_addr = 0x0100007fu;
            if (u != INVALID_SOCKET && !W.connect_(u, (struct sockaddr *)&a, sizeof a)) relay(c, u, t->stop);
            if (u != INVALID_SOCKET) W.close_(u);
        } else Sleep(50);
        W.shutdown_(c, SD_SEND); W.close_(c);
    }
    return 0;
}
tp_srv *tp_start(const char *reply, unsigned short target_port) {
    if (!tls_ws_ok()) return NULL;
    tp_srv *t = calloc(1, sizeof *t);
    snprintf(t->reply, sizeof t->reply, "%s", reply); t->target = target_port;
    t->ls = listen_loopback(&t->port);
    if (t->ls == INVALID_SOCKET) { free(t); return NULL; }
    InitializeCriticalSection(&t->cs);
    t->stop = CreateEventA(NULL, TRUE, FALSE, NULL);
    t->thr = CreateThread(NULL, 0, tp_thread, t, 0, NULL);
    return t;
}
unsigned short tp_port(tp_srv *p) { return p->port; }
int tp_count(tp_srv *p) { EnterCriticalSection(&p->cs); int n = p->n; LeaveCriticalSection(&p->cs); return n; }
int tp_wait(tp_srv *p, int n, DWORD ms) { DWORD t0 = GetTickCount(); while (tp_count(p) < n) { if (GetTickCount() - t0 > ms) return 0; Sleep(10); } return 1; }
const char *tp_head(tp_srv *p, int i) { return (i >= 0 && i < TP_MAX && i < tp_count(p)) ? p->head[i] : NULL; }
void tp_stop(tp_srv *p) {
    if (!p) return;
    SetEvent(p->stop);
    if (WaitForSingleObject(p->thr, 5000) != WAIT_OBJECT_0) { t_note("tp: proxy thread did not exit (leaked)"); return; }
    CloseHandle(p->thr); CloseHandle(p->stop); W.close_(p->ls); DeleteCriticalSection(&p->cs); free(p);
}
