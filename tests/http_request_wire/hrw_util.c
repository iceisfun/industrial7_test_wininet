/* hrw_util.c - helpers for the http_request_wire area (see hrw.h). */
#include "hrw.h"
#include <stdlib.h>

static const srv_step g_ok_steps[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "ok"), S_CLOSE_IF_ASKED(), S_LOOP() };

srv *hrw_srv_steps(const srv_step *st, int n) {
    srv_script *sc = (srv_script *)calloc(1, sizeof *sc);  /* leaked on purpose: tiny, must outlive the server */
    sc->steps = st; sc->nsteps = n;
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTP; cfg.scripts = sc; cfg.nscripts = 1;
    srv *s = NULL;
    if (srv_start(&cfg, &s) != SRV_OK) return NULL;
    return s;
}
srv *hrw_srv(void) { return hrw_srv_steps(g_ok_steps, 5); }
srv *hrw_srv_call(srv_step_fn fn, void *user) {
    srv_step *st = (srv_step *)calloc(2, sizeof *st);
    st[0].op = SRV_CALL; st[0].fn = fn;
    st[1].op = SRV_END;
    srv_script *sc = (srv_script *)calloc(1, sizeof *sc);
    sc->steps = st; sc->nsteps = 2;
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTP; cfg.scripts = sc; cfg.nscripts = 1; cfg.user = user;
    srv *s = NULL;
    if (srv_start(&cfg, &s) != SRV_OK) return NULL;
    return s;
}

int hrw_open_host(hrw *w, srv *s, const char *agent, const char *host, const char *verb, const char *obj, DWORD flags) {
    memset(w, 0, sizeof *w);
    w->s = s;
    t_net_prepare();
    w->hi = t_inet_open_ex(agent, INTERNET_OPEN_TYPE_DIRECT, 0, 5000);
    if (!w->hi) return 0;
    w->hc = U(InternetConnectA)(w->hi, host, srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!w->hc) return 0;
    w->hr = U(HttpOpenRequestA)(w->hc, verb, obj, NULL, NULL, NULL, flags, 0);
    return w->hr != NULL;
}

int hrw_open(hrw *w, srv *s, const char *agent, const char *verb, const char *obj, const char *ver,
             const char *ref, const char **accept, DWORD flags) {
    memset(w, 0, sizeof *w);
    w->s = s;
    t_net_prepare();
    w->hi = t_inet_open_ex(agent, INTERNET_OPEN_TYPE_DIRECT, 0, 5000);
    if (!w->hi) return 0;
    w->hc = U(InternetConnectA)(w->hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!w->hc) return 0;
    w->hr = U(HttpOpenRequestA)(w->hc, verb, obj, ver, ref, accept, flags, 0);
    return w->hr != NULL;
}

BOOL hrw_send(hrw *w, const char *hdrs, DWORD hlen, const void *opt, DWORD optlen) {
    SetLastError(0);
    w->ok = U(HttpSendRequestA)(w->hr, hdrs, hlen, (LPVOID)opt, optlen);
    w->err = w->ok ? 0 : GetLastError();
    w->status = 0;
    if (w->ok) {
        DWORD st = 0, l = sizeof st;
        if (U(HttpQueryInfoA)(w->hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL)) w->status = (int)st;
    }
    return w->ok;
}

void hrw_read(hrw *w) { int ok; w->nbody = t_inet_read_all(w->hr, w->body, sizeof w->body, &ok); }

void hrw_close_handles(hrw *w) {
    if (w->hr) U(InternetCloseHandle)(w->hr);
    if (w->hc) U(InternetCloseHandle)(w->hc);
    if (w->hi) U(InternetCloseHandle)(w->hi);
    w->hr = w->hc = w->hi = NULL;
}
void hrw_done(hrw *w) { hrw_close_handles(w); if (w->s) srv_stop(w->s); w->s = NULL; }

int hrw_simple(hrw *w, const char *agent, const char *verb, const char *obj, const char *ver, const char *ref,
               const char **accept, DWORD flags, const char *hdrs, const void *opt, DWORD optlen) {
    srv *s = hrw_srv();
    if (!s) { memset(w, 0, sizeof *w); return -1; }
    if (!hrw_open(w, s, agent, verb, obj, ver, ref, accept, flags)) { t_check(0, __FILE__, __LINE__, "hrw_open", "err=%lu", GetLastError()); return 0; }
    hrw_send(w, hdrs, hdrs ? (DWORD)-1 : 0, opt, optlen);
    t_check(w->ok, __FILE__, __LINE__, "HttpSendRequestA", "err=%lu %s", w->err, t_inet_errname(w->err));
    if (w->ok) hrw_read(w);
    return srv_wait_requests(s, 1, 3000);
}

const char *hrw_names(srv *s, int i) {
    static char b[8][2048]; static volatile LONG k;
    char *o = b[InterlockedIncrement(&k) & 7]; size_t n = 0; o[0] = 0;
    int c = srv_req_header_count(s, i);
    for (int h = 0; h < c; h++) {
        const char *nm = srv_req_header_name(s, i, h);
        n += snprintf(o + n, 2048 - n, "%s%s", h ? "|" : "", nm ? nm : "?");
        if (n >= 2000) break;
    }
    return o;
}
const char *hrw_hostport(srv *s) { static char b[4][64]; static volatile LONG k; char *o = b[InterlockedIncrement(&k) & 3]; snprintf(o, 64, "127.0.0.1:%u", srv_port(s)); return o; }

const char *hrw_raw(srv *s, int i) {
    static char b[4][16384]; static volatile LONG k;
    char *o = b[InterlockedIncrement(&k) & 3]; size_t n = 0;
    const char *r = srv_req_head_raw(s, i, &n);
    if (!r) { o[0] = 0; return o; }
    if (n > sizeof b[0] - 1) n = sizeof b[0] - 1;
    memcpy(o, r, n); o[n] = 0;
    return o;
}

void hrw_dump(srv *s, int i) {
    size_t n = 0; const char *r = srv_req_head_raw(s, i, &n);
    if (!r) { t_note("req %d: (none)", i); return; }
    char o[4096]; size_t k = 0;
    for (size_t j = 0; j < n && k < sizeof o - 8; j++) {
        unsigned char c = (unsigned char)r[j];
        if (c == '\r') { o[k++] = '\\'; o[k++] = 'r'; }
        else if (c == '\n') { o[k++] = '\\'; o[k++] = 'n'; }
        else if (c < 0x20 || c >= 0x7f) k += snprintf(o + k, sizeof o - k, "\\x%02x", c);
        else o[k++] = (char)c;
    }
    o[k] = 0;
    t_note("req %d conn %d: %s", i, srv_req_conn(s, i), o);
}

HINTERNET hrw_proxy_session(srv *s, const char *agent) {
    char px[64]; snprintf(px, sizeof px, "http=127.0.0.1:%u", srv_port(s));
    t_net_prepare();
    HINTERNET h = U(InternetOpenA)(agent ? agent : "hrw-proxy", INTERNET_OPEN_TYPE_PROXY, px, "", 0);
    if (h) {
        DWORD to = 5000;
        U(InternetSetOptionA)(h, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
        U(InternetSetOptionA)(h, INTERNET_OPTION_SEND_TIMEOUT, &to, sizeof to);
        U(InternetSetOptionA)(h, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
    }
    return h;
}

int hrw_get_dword_opt(HINTERNET h, DWORD opt, DWORD *v) { DWORD l = sizeof *v; return U(InternetQueryOptionA)(h, opt, v, &l); }

volatile int hrw_trace;
static DWORD WINAPI guard_thread(void *p) { ((void (*)(void))p)(); return 0; }
int hrw_guard(const char *name, void (*fn)(void), DWORD ms) {
    hrw_trace = 1;
    HANDLE th = CreateThread(NULL, 0, guard_thread, (void *)fn, 0, NULL);
    if (!th) { fn(); hrw_trace = 0; return 1; }
    DWORD r = WaitForSingleObject(th, ms);
    CloseHandle(th);
    hrw_trace = 0;
    t_check(r == WAIT_OBJECT_0, __FILE__, __LINE__, "guarded test finished", "%s still running after %lu ms (hang)", name, ms);
    return r == WAIT_OBJECT_0;
}
