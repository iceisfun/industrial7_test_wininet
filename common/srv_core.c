/* srv_core.c - listener, threads, recorder, accessors, small data helpers. See srv.h / SRV.md. */
#include "srv_int.h"

srv_ws_api SWS; srv_crypt_api SCR; srv_ncrypt_api SNC; PSecurityFunctionTableW SSP;
static CRITICAL_SECTION g_load_cs; static volatile LONG g_load_init;
static void load_lock(void) {
    if (InterlockedCompareExchange(&g_load_init, 1, 0) == 0) { InitializeCriticalSection(&g_load_cs); g_load_init = 2; }
    while (g_load_init != 2) Sleep(1);
    EnterCriticalSection(&g_load_cs);
}
#define SRV_RES(f) if (!(api.f = (__typeof__(api.f))GetProcAddress(m, #f))) ok = 0;
int srv_ws_load(void) {
    load_lock();
    if (!SWS.tried) {
        srv_ws_api api; memset(&api, 0, sizeof api); int ok = 1;
        HMODULE m = LoadLibraryA("ws2_32.dll");
        if (!m) ok = 0; else { SRV_WS_FUNCS(SRV_RES) }
        if (ok) { WSADATA wd; ok = api.WSAStartup(MAKEWORD(2, 2), &wd) == 0; }
        api.tried = 1; api.ok = ok; SWS = api;
    }
    LeaveCriticalSection(&g_load_cs);
    return SWS.ok;
}
int srv_crypt_load(void) {
    load_lock();
    if (!SCR.tried) {
        srv_crypt_api api; memset(&api, 0, sizeof api); int ok = 1;
        HMODULE m = LoadLibraryA("crypt32.dll");
        if (!m) ok = 0; else { SRV_CRYPT_FUNCS(SRV_RES) }
        api.tried = 1; api.ok = ok; SCR = api;
        srv_ncrypt_api napi; memset(&napi, 0, sizeof napi);
        { srv_ncrypt_api api; memset(&api, 0, sizeof api); int ok = 1; HMODULE m = LoadLibraryA("ncrypt.dll");
          if (!m) ok = 0; else { SRV_NCRYPT_FUNCS(SRV_RES) } api.tried = 1; api.ok = ok; napi = api; }
        SNC = napi;
    }
    LeaveCriticalSection(&g_load_cs);
    return SCR.ok;
}
int srv_sspi_load(void) {
    static int tried;
    load_lock();
    if (!tried) {
        tried = 1;
        const char *dlls[] = { "sspicli.dll", "secur32.dll", NULL };
        for (int i = 0; dlls[i] && !SSP; i++) {
            HMODULE m = LoadLibraryA(dlls[i]); if (!m) continue;
            INIT_SECURITY_INTERFACE_W init = (INIT_SECURITY_INTERFACE_W)GetProcAddress(m, "InitSecurityInterfaceW");
            if (init) SSP = init();
        }
        if (SSP && (!SSP->AcquireCredentialsHandleW || !SSP->AcceptSecurityContext || !SSP->DecryptMessage ||
                    !SSP->EncryptMessage || !SSP->QueryContextAttributesW || !SSP->FreeContextBuffer ||
                    !SSP->DeleteSecurityContext || !SSP->FreeCredentialsHandle)) SSP = NULL;
    }
    LeaveCriticalSection(&g_load_cs);
    return SSP != NULL;
}

/* ------------------------------------------------------------------ sockets */
void srv_set_timeouts(SOCKET so, DWORD ms) {
    SWS.setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, sizeof ms);
    SWS.setsockopt(so, SOL_SOCKET, SO_SNDTIMEO, (char *)&ms, sizeof ms);
}
static SOCKET listen_af(int af, unsigned short port, unsigned short *outport) {
    SOCKET l = SWS.socket(af, SOCK_STREAM, IPPROTO_TCP);
    if (l == INVALID_SOCKET) return l;
    BOOL one = TRUE; SWS.setsockopt(l, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&one, sizeof one);
    int r;
    if (af == AF_INET) {
        struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = srv_htons(port);
        a.sin_addr.s_addr = 0x0100007f; /* 127.0.0.1 in network order */
        r = SWS.bind(l, (struct sockaddr *)&a, sizeof a);
    } else {
        struct sockaddr_in6 a; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_port = srv_htons(port);
        a.sin6_addr.s6_addr[15] = 1;
        r = SWS.bind(l, (struct sockaddr *)&a, sizeof a);
    }
    if (r || SWS.listen(l, 16)) { SWS.closesocket(l); return INVALID_SOCKET; }
    if (outport) {
        struct sockaddr_storage ss; int sl = sizeof ss;
        if (SWS.getsockname(l, (struct sockaddr *)&ss, &sl)) { SWS.closesocket(l); return INVALID_SOCKET; }
        *outport = srv_htons(((struct sockaddr_in *)&ss)->sin_port); /* same offset for v4 and v6 */
    }
    return l;
}
SOCKET srv_listen_v4(unsigned short *port) { return listen_af(AF_INET, 0, port); }

int srv_wait_stop(srv *s, DWORD ms) { return WaitForSingleObject(s->stop_ev, ms) == WAIT_OBJECT_0 || s->stop; }

/* Accept on any of ls[] within ms; polls in 100 ms steps so srv_stop is noticed. */
SOCKET srv_accept_bounded(srv *s, SOCKET *ls, int nls, DWORD ms) {
    DWORD t0 = GetTickCount();
    for (;;) {
        if (s->stop) return INVALID_SOCKET;
        fd_set rs; rs.fd_count = 0;
        for (int i = 0; i < nls; i++) if (ls[i] != INVALID_SOCKET) rs.fd_array[rs.fd_count++] = ls[i];
        if (!rs.fd_count) return INVALID_SOCKET;
        struct timeval tv = { 0, 100000 };
        int r = SWS.select(0, &rs, NULL, NULL, &tv);
        if (r > 0) {
            for (u_int i = 0; i < rs.fd_count; i++) {
                SOCKET c = SWS.accept(rs.fd_array[i], NULL, NULL);
                if (c != INVALID_SOCKET) return c;
            }
        } else if (r < 0) Sleep(20);
        if (GetTickCount() - t0 >= ms) return INVALID_SOCKET;
    }
}

/* ------------------------------------------------------------------ recorder */
void srv_keep(srv *s, void *p) {
    EnterCriticalSection(&s->cs);
    if (s->nkeep == s->capkeep) { s->capkeep = s->capkeep ? s->capkeep * 2 : 64; s->keep = realloc(s->keep, s->capkeep * sizeof *s->keep); }
    s->keep[s->nkeep++] = p;
    LeaveCriticalSection(&s->cs);
}
void srv_record(srv *s, srv_ev_kind k, int conn, int req, const void *data, size_t n) {
    char *copy = NULL;
    if (data) { copy = malloc(n + 1); memcpy(copy, data, n); copy[n] = 0; }
    EnterCriticalSection(&s->cs);
    if (s->nev == s->capev) { s->capev = s->capev ? s->capev * 2 : 64; s->ev = realloc(s->ev, s->capev * sizeof *s->ev); }
    srv_event *e = &s->ev[s->nev++];
    e->kind = k; e->conn = conn; e->req = req; e->data = copy; e->n = data ? n : 0; e->t_ms = GetTickCount() - s->t0;
    LeaveCriticalSection(&s->cs);
}
void srv_recordf(srv *s, srv_ev_kind k, int conn, const char *fmt, ...) {
    char t[512]; va_list a; va_start(a, fmt); int n = vsnprintf(t, sizeof t, fmt, a); va_end(a);
    if (n < 0) n = 0; if (n >= (int)sizeof t) n = sizeof t - 1;
    srv_record(s, k, conn, -1, t, n);
}
int srv_add_req(srv *s, srv_req *r) {
    EnterCriticalSection(&s->cs);
    if (s->nreq == s->capreq) { s->capreq = s->capreq ? s->capreq * 2 : 32; s->req = realloc(s->req, s->capreq * sizeof *s->req); }
    int i = s->nreq; s->req[s->nreq++] = r;
    LeaveCriticalSection(&s->cs);
    return i;
}
srv_req *srv_get_req(srv *s, int i) {
    srv_req *r = NULL;
    if (!s) return NULL;
    EnterCriticalSection(&s->cs);
    if (i >= 0 && i < s->nreq) r = s->req[i];
    LeaveCriticalSection(&s->cs);
    return r;
}
int srv_count_events(srv *s, srv_ev_kind k) {
    int n = 0; if (!s) return 0;
    EnterCriticalSection(&s->cs);
    for (int i = 0; i < s->nev; i++) if (k == SRV_EV_ANY || s->ev[i].kind == k) n++;
    LeaveCriticalSection(&s->cs);
    return n;
}
int srv_wait_events(srv *s, srv_ev_kind k, int count, DWORD timeout_ms) {
    DWORD t0 = GetTickCount();
    if (!s) return 0;
    if (timeout_ms > 30000) timeout_ms = 30000;
    for (;;) {
        if (srv_count_events(s, k) >= count) return 1;
        if (GetTickCount() - t0 >= timeout_ms) return 0;
        Sleep(5);
    }
}
int srv_req_count(srv *s) { int n; if (!s) return 0; EnterCriticalSection(&s->cs); n = s->nreq; LeaveCriticalSection(&s->cs); return n; }
int srv_wait_requests(srv *s, int count, DWORD timeout_ms) {
    DWORD t0 = GetTickCount();
    if (!s) return 0;
    if (timeout_ms > 30000) timeout_ms = 30000;
    for (;;) {
        if (srv_req_count(s) >= count) return 1;
        if (GetTickCount() - t0 >= timeout_ms) return 0;
        Sleep(5);
    }
}
int srv_events(srv *s, const srv_event **ev) {
    if (!s) { *ev = NULL; return 0; }
    EnterCriticalSection(&s->cs);
    int n = s->nev; srv_event *copy = malloc((n ? n : 1) * sizeof *copy);
    memcpy(copy, s->ev, n * sizeof *copy);
    LeaveCriticalSection(&s->cs);
    srv_keep(s, copy);
    *ev = copy; return n;
}
const char *srv_event_kind_name(srv_ev_kind k) {
    static const char *n[] = { "ANY", "ACCEPT", "HEAD", "BODY", "BYTES", "EOF", "RESET", "TIMEOUT", "ERROR", "TLS_DONE",
                               "TLS_ABORT", "SCRIPT_DONE", "MISMATCH", "FTP_CMD", "FTP_DATA", "AUTH", "SENT", "CLOSED" };
    return (unsigned)k < sizeof n / sizeof n[0] ? n[k] : "?";
}
int srv_conn_count(srv *s) { int n; if (!s) return 0; EnterCriticalSection(&s->cs); n = s->nconn; LeaveCriticalSection(&s->cs); return n; }
void srv_dump(srv *s) {
    const srv_event *ev; int n = srv_events(s, &ev);
    for (int i = 0; i < n; i++) {
        char esc[200]; size_t o = 0;
        for (size_t j = 0; ev[i].data && j < ev[i].n && o < sizeof esc - 5; j++) {
            unsigned char ch = ev[i].data[j];
            if (ch == '\r') { esc[o++] = '\\'; esc[o++] = 'r'; }
            else if (ch == '\n') { esc[o++] = '\\'; esc[o++] = 'n'; }
            else if (ch < 32 || ch > 126) esc[o++] = '.';
            else esc[o++] = ch;
        }
        esc[o] = 0;
        t_note("srv ev %d t=%lu conn=%d req=%d %s n=%u [%s]", i, ev[i].t_ms, ev[i].conn, ev[i].req,
               srv_event_kind_name(ev[i].kind), (unsigned)ev[i].n, esc);
    }
}

/* request accessors */
int srv_req_conn(srv *s, int i) { srv_req *r = srv_get_req(s, i); return r ? r->conn : -1; }
const char *srv_req_line(srv *s, int i) { srv_req *r = srv_get_req(s, i); return r ? r->line : NULL; }
const char *srv_req_method(srv *s, int i) { srv_req *r = srv_get_req(s, i); return r ? r->method : NULL; }
const char *srv_req_target(srv *s, int i) { srv_req *r = srv_get_req(s, i); return r ? r->target : NULL; }
int srv_req_header_count(srv *s, int i) { srv_req *r = srv_get_req(s, i); return r ? r->nh : -1; }
const char *srv_req_header_name(srv *s, int i, int h) { srv_req *r = srv_get_req(s, i); return r && h >= 0 && h < r->nh ? r->hn[h] : NULL; }
const char *srv_req_header_value(srv *s, int i, int h) { srv_req *r = srv_get_req(s, i); return r && h >= 0 && h < r->nh ? r->hv[h] : NULL; }
int srv_req_header_index(srv *s, int i, const char *name) {
    srv_req *r = srv_get_req(s, i); if (!r) return -1;
    for (int h = 0; h < r->nh; h++) if (!_stricmp(r->hn[h], name)) return h;
    return -1;
}
const char *srv_req_header(srv *s, int i, const char *name) { int h = srv_req_header_index(s, i, name); return h < 0 ? NULL : srv_req_header_value(s, i, h); }
int srv_req_header_occurrences(srv *s, int i, const char *name) {
    srv_req *r = srv_get_req(s, i); int n = 0; if (!r) return -1;
    for (int h = 0; h < r->nh; h++) if (!_stricmp(r->hn[h], name)) n++;
    return n;
}
const char *srv_req_head_raw(srv *s, int i, size_t *n) { srv_req *r = srv_get_req(s, i); if (n) *n = r ? r->nhead : 0; return r ? r->head : NULL; }
const char *srv_req_body(srv *s, int i, size_t *n) {
    srv_req *r = srv_get_req(s, i); const char *b = NULL; size_t l = 0;
    if (r) { EnterCriticalSection(&s->cs); if (r->has_body) { b = r->body; l = r->nbody; } LeaveCriticalSection(&s->cs); }
    if (n) *n = l; return b;
}
const char *srv_req_body_raw(srv *s, int i, size_t *n) {
    srv_req *r = srv_get_req(s, i); const char *b = NULL; size_t l = 0;
    if (r) { EnterCriticalSection(&s->cs); if (r->has_body) { b = r->body_raw; l = r->nbody_raw; } LeaveCriticalSection(&s->cs); }
    if (n) *n = l; return b;
}
int srv_req_body_chunked(srv *s, int i) { srv_req *r = srv_get_req(s, i); return r ? r->chunked : -1; }

/* ------------------------------------------------------------------ threads */
static DWORD WINAPI conn_thread(LPVOID p) {
    srv_conn *c = p; srv *s = c->s;
    srv_record(s, SRV_EV_ACCEPT, c->id, -1, NULL, 0);
    if (s->kind == SRV_FTP) srv_ftp_conn(c);
    else {
        if (s->kind == SRV_HTTPS) { c->tls = 1; if (srv_tls_accept(c)) goto done; }
        srv_http_conn(c);
        if (c->tls) srv_tls_shutdown(c);
    }
done:
    EnterCriticalSection(&s->cs);
    if (c->sock != INVALID_SOCKET) {
        /* graceful: stop sending, drain a little so the client sees FIN not RST */
        SOCKET so = c->sock;
        LeaveCriticalSection(&s->cs);
        SWS.shutdown(so, SD_SEND);
        DWORD shortto = 200; SWS.setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, (char *)&shortto, sizeof shortto);
        char d[512]; for (int g = 0; g < 16 && SWS.recv(so, d, sizeof d, 0) > 0; g++) ;
        EnterCriticalSection(&s->cs);
        if (c->sock != INVALID_SOCKET) { SWS.closesocket(c->sock); c->sock = INVALID_SOCKET; }
    }
    LeaveCriticalSection(&s->cs);
    srv_record(s, SRV_EV_CLOSED, c->id, -1, NULL, 0);
    if (c->tls) srv_tls_free(c);
    InterlockedExchange(&c->done, 1);
    return 0;
}

static void kill_conns(srv *s) {
    EnterCriticalSection(&s->cs);
    for (int i = 0; i < s->nconn; i++) if (s->conns[i]->sock != INVALID_SOCKET) SWS.shutdown(s->conns[i]->sock, SD_BOTH);
    LeaveCriticalSection(&s->cs);
}

static DWORD WINAPI accept_thread(LPVOID p) {
    srv *s = p; SOCKET ls[2] = { s->l4, s->l6 };
    while (!s->stop) {
        if (GetTickCount() - s->t0 >= s->cfg.lifetime_ms) { srv_recordf(s, SRV_EV_ERROR, -1, "lifetime expired"); kill_conns(s); break; }
        SOCKET c = srv_accept_bounded(s, ls, 2, 100);
        if (c == INVALID_SOCKET) continue;
        EnterCriticalSection(&s->cs);
        if (s->nconn >= SRV_MAXCONN || s->stop) { LeaveCriticalSection(&s->cs); SWS.closesocket(c); continue; }
        srv_conn *cn = calloc(1, sizeof *cn);
        cn->s = s; cn->id = s->nconn; cn->sock = c; cn->last_req = -1;
        int ns = s->cfg.nscripts;
        cn->sc = ns ? &s->cfg.scripts[cn->id < ns ? cn->id : ns - 1] : NULL;
        s->conns[s->nconn++] = cn;
        LeaveCriticalSection(&s->cs);
        srv_set_timeouts(c, s->cfg.io_timeout_ms);
        BOOL nd = TRUE; SWS.setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&nd, sizeof nd);
        cn->thr = CreateThread(NULL, 0, conn_thread, cn, 0, NULL);
        if (!cn->thr) { EnterCriticalSection(&s->cs); SWS.closesocket(c); cn->sock = INVALID_SOCKET; cn->done = 1; LeaveCriticalSection(&s->cs); }
    }
    return 0;
}

const char *srv_strerror(int rc) {
    switch (rc) {
    case SRV_OK: return "ok"; case SRV_E_UNAVAILABLE: return "server APIs unavailable";
    case SRV_E_BIND: return "cannot bind loopback"; case SRV_E_CERT: return "cannot create certificate";
    case SRV_E_ARG: return "bad argument"; default: return "?";
    }
}

static volatile LONG g_last_rc;
int srv_last_error(void) { return g_last_rc; }
static int srv_start_impl(const srv_config *cfg, srv **out);
int srv_start(const srv_config *cfg, srv **out) { int rc = srv_start_impl(cfg, out); g_last_rc = rc; return rc; }
static int srv_start_impl(const srv_config *cfg, srv **out) {
    *out = NULL;
    if (!cfg || cfg->kind > SRV_FTP) return SRV_E_ARG;
    if (!srv_ws_load()) return SRV_E_UNAVAILABLE;
    srv *s = calloc(1, sizeof *s);
    s->cfg = *cfg; s->kind = cfg->kind;
    if (!s->cfg.lifetime_ms) s->cfg.lifetime_ms = 20000;
    if (s->cfg.lifetime_ms > 120000) s->cfg.lifetime_ms = 120000;
    if (!s->cfg.io_timeout_ms) s->cfg.io_timeout_ms = 5000;
    InitializeCriticalSection(&s->cs);
    s->l4 = s->l6 = INVALID_SOCKET;
    s->stop_ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    int rc = SRV_OK;
    if (s->kind == SRV_HTTPS && (rc = srv_tls_cred(s)) != SRV_OK) goto fail;
    if (s->kind == SRV_FTP && (rc = srv_ftp_init(s)) != SRV_OK) goto fail;
    rc = SRV_E_BIND;
    for (int attempt = 0; attempt < 8; attempt++) {
        s->l4 = listen_af(AF_INET, 0, &s->port);
        if (s->l4 == INVALID_SOCKET) continue;
        if (s->cfg.v4_only) break;
        s->l6 = listen_af(AF_INET6, s->port, NULL);
        if (s->l6 != INVALID_SOCKET) { s->v6 = 1; break; }
        if (attempt == 7) break;               /* keep v4-only on the last attempt */
        SWS.closesocket(s->l4); s->l4 = INVALID_SOCKET;
    }
    if (s->l4 == INVALID_SOCKET) goto fail;
    if (!s->cfg.v4_only && !s->v6) t_note("srv: [::1] unavailable, v4-only server (localhost URLs cost ~2 s, see 04 F2)");
    s->t0 = GetTickCount();
    s->accept_thr = CreateThread(NULL, 0, accept_thread, s, 0, NULL);
    if (!s->accept_thr) goto fail;
    *out = s; return SRV_OK;
fail:
    if (s->l4 != INVALID_SOCKET) SWS.closesocket(s->l4);
    if (s->l6 != INVALID_SOCKET) SWS.closesocket(s->l6);
    if (s->kind == SRV_HTTPS) srv_tls_cred_free(s);
    if (s->kind == SRV_FTP) srv_ftp_free(s);
    CloseHandle(s->stop_ev); DeleteCriticalSection(&s->cs); free(s);
    return rc;
}

static void free_req(srv_req *r) {
    free(r->head); free(r->line); free(r->method); free(r->target);
    for (int h = 0; h < r->nh; h++) { free(r->hn[h]); free(r->hv[h]); }
    free(r->hn); free(r->hv); free(r->body); free(r->body_raw); free(r);
}

void srv_stop(srv *s) {
    if (!s) return;
    InterlockedExchange(&s->stop, 1); SetEvent(s->stop_ev);
    DWORD t0 = GetTickCount();
    if (WaitForSingleObject(s->accept_thr, 1500) != WAIT_OBJECT_0) t_note("srv: accept thread slow to stop");
    if (s->l4 != INVALID_SOCKET) SWS.closesocket(s->l4);
    if (s->l6 != INVALID_SOCKET) SWS.closesocket(s->l6);
    s->l4 = s->l6 = INVALID_SOCKET;
    kill_conns(s);
    int leak = 0;
    EnterCriticalSection(&s->cs); int nc = s->nconn; LeaveCriticalSection(&s->cs);
    for (int i = 0; i < nc; i++) {
        srv_conn *c = s->conns[i];
        if (!c->thr) continue;
        DWORD el = GetTickCount() - t0, left = el < 3000 ? 3000 - el : 0;
        if (WaitForSingleObject(c->thr, left) != WAIT_OBJECT_0) {
            /* still blocked: close the socket to force it out, give it a little more */
            EnterCriticalSection(&s->cs);
            if (c->sock != INVALID_SOCKET) { SWS.closesocket(c->sock); c->sock = INVALID_SOCKET; }
            LeaveCriticalSection(&s->cs);
            if (WaitForSingleObject(c->thr, 500) != WAIT_OBJECT_0) { leak = 1; continue; }
        }
    }
    if (WaitForSingleObject(s->accept_thr, 0) != WAIT_OBJECT_0) leak = 1;
    if (leak) { t_note("srv: thread leak (server object intentionally leaked)"); return; }
    CloseHandle(s->accept_thr);
    for (int i = 0; i < nc; i++) { srv_conn *c = s->conns[i]; if (c->thr) CloseHandle(c->thr); free(c->in); free(c->raw); free(c->extra_hdr); free(c); }
    for (int i = 0; i < s->nev; i++) free((void *)s->ev[i].data);
    for (int i = 0; i < s->nreq; i++) free_req(s->req[i]);
    for (int i = 0; i < s->nkeep; i++) free(s->keep[i]);
    for (int i = 0; i < s->nftpcmd; i++) free(s->ftpcmd[i]);
    free(s->ev); free(s->req); free(s->keep); free(s->ftpcmd);
    if (s->kind == SRV_HTTPS) srv_tls_cred_free(s);
    if (s->kind == SRV_FTP) srv_ftp_free(s);
    CloseHandle(s->stop_ev); DeleteCriticalSection(&s->cs); free(s);
}

unsigned short srv_port(const srv *s) { return s ? s->port : 0; }
int srv_has_v6(const srv *s) { return s && s->v6; }
static const char *scheme(const srv *s) { return s->kind == SRV_HTTPS ? "https" : s->kind == SRV_FTP ? "ftp" : "http"; }
const char *srv_url_host(srv *s, const char *host, const char *path) {
    char *b = s->url[InterlockedIncrement(&s->urli) & 7];
    snprintf(b, sizeof s->url[0], "%s://%s:%u%s", scheme(s), host, s->port, path ? path : "/");
    return b;
}
const char *srv_url(srv *s, const char *path) { return srv_url_host(s, "127.0.0.1", path); }
const char *srv_hostport(srv *s) { snprintf(s->hp, sizeof s->hp, "127.0.0.1:%u", s->port); return s->hp; }

srv *srv_http(const srv_step *steps, int nsteps) {
    srv_script *sc = NULL; srv_config cfg; memset(&cfg, 0, sizeof cfg); cfg.kind = SRV_HTTP;
    if (steps) { static srv_script scs[64]; static LONG k; sc = &scs[InterlockedIncrement(&k) & 63]; sc->steps = steps; sc->nsteps = nsteps; cfg.scripts = sc; cfg.nscripts = 1; }
    srv *s; return srv_start(&cfg, &s) == SRV_OK ? s : NULL;
}
srv *srv_https(const srv_step *steps, int nsteps, int profile) {
    srv_script *sc = NULL; srv_config cfg; memset(&cfg, 0, sizeof cfg); cfg.kind = SRV_HTTPS; cfg.cert_profile = profile;
    if (steps) { static srv_script scs[64]; static LONG k; sc = &scs[InterlockedIncrement(&k) & 63]; sc->steps = steps; sc->nsteps = nsteps; cfg.scripts = sc; cfg.nscripts = 1; }
    srv *s; return srv_start(&cfg, &s) == SRV_OK ? s : NULL;
}

/* ------------------------------------------------------------------ data helpers */
int srv_pattern_check(const void *p, size_t n, size_t off) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) if (b[i] != srv_pattern_byte(off + i)) return 0;
    return 1;
}
unsigned long srv_crc32(const void *p, size_t n) {
    static unsigned long tab[256]; static int init;
    if (!init) { for (unsigned long i = 0; i < 256; i++) { unsigned long c = i; for (int k = 0; k < 8; k++) c = c & 1 ? 0xedb88320UL ^ (c >> 1) : c >> 1; tab[i] = c; } init = 1; }
    unsigned long c = 0xffffffffUL; const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) c = tab[(c ^ b[i]) & 0xff] ^ (c >> 8);
    return c ^ 0xffffffffUL;
}
unsigned char *srv_deflate_stored(const void *p, size_t n, int mode, size_t *outn) {
    size_t blocks = n / 65535 + 1, cap = n + blocks * 5 + 32, o = 0;
    unsigned char *b = malloc(cap); const unsigned char *src = p;
    if (mode == 0) { const unsigned char h[10] = { 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff }; memcpy(b, h, 10); o = 10; }
    else if (mode == 1) { b[o++] = 0x78; b[o++] = 0x01; }
    size_t off = 0;
    do {
        size_t len = n - off > 65535 ? 65535 : n - off; int last = off + len >= n;
        b[o++] = last ? 1 : 0; b[o++] = len & 0xff; b[o++] = len >> 8; b[o++] = ~len & 0xff; b[o++] = (~len >> 8) & 0xff;
        memcpy(b + o, src + off, len); o += len; off += len;
    } while (off < n);
    if (mode == 0) {
        unsigned long c = srv_crc32(p, n);
        for (int i = 0; i < 4; i++) b[o++] = (c >> (8 * i)) & 0xff;
        for (int i = 0; i < 4; i++) b[o++] = ((unsigned long)n >> (8 * i)) & 0xff;
    } else if (mode == 1) {
        unsigned long a = 1, bb = 0;
        for (size_t i = 0; i < n; i++) { a = (a + src[i]) % 65521; bb = (bb + a) % 65521; }
        unsigned long ad = (bb << 16) | a;
        for (int i = 3; i >= 0; i--) b[o++] = (ad >> (8 * i)) & 0xff;
    }
    *outn = o; return b;
}
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char *srv_b64(const void *p, size_t n) {
    const unsigned char *b = p; char *o = malloc(n / 3 * 4 + 8), *q = o;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = b[i] << 16 | (i + 1 < n ? b[i + 1] << 8 : 0) | (i + 2 < n ? b[i + 2] : 0);
        *q++ = B64[v >> 18]; *q++ = B64[(v >> 12) & 63];
        *q++ = i + 1 < n ? B64[(v >> 6) & 63] : '='; *q++ = i + 2 < n ? B64[v & 63] : '=';
    }
    *q = 0; return o;
}
unsigned char *srv_unb64(const char *s, size_t *n) {
    size_t l = strlen(s); unsigned char *o = malloc(l / 4 * 3 + 4); size_t k = 0; unsigned v = 0; int bits = 0;
    for (size_t i = 0; i < l; i++) {
        char ch = s[i]; const char *p;
        if (ch == '=' || ch == ' ' || ch == '\r' || ch == '\n') { if (ch == '=') break; continue; }
        if (!ch || !(p = strchr(B64, ch))) { free(o); return NULL; }
        v = v << 6 | (unsigned)(p - B64); bits += 6;
        if (bits >= 8) { bits -= 8; o[k++] = (v >> bits) & 0xff; }
    }
    if (n) *n = k; return o;
}
const char *srv_fox_text(void) {
    static char t[SRV_FOX_LEN + 1];
    if (!t[0]) { for (int i = 0; i < 20; i++) memcpy(t + i * 45, SRV_FOX_TEXT, 45); t[SRV_FOX_LEN] = 0; }
    return t;
}
