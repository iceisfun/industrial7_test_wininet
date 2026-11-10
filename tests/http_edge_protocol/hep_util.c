/* hep_util.c - helpers for the http_edge_protocol area (see hep.h).
 * VM_TIMEOUT: 720 */
#include "hep.h"
#include <stdlib.h>

/* ---------------------------------------------------------------- servers */
hep_srv *hep_start_v4(const srv_step *st, int n, int v4_only) {
    hep_srv *h = (hep_srv *)calloc(1, sizeof *h);
    h->steps = (srv_step *)calloc((size_t)n + 1, sizeof *h->steps);
    memcpy(h->steps, st, (size_t)n * sizeof *st);
    h->nsteps = n;
    h->sc.steps = h->steps; h->sc.nsteps = n;
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTP; cfg.scripts = &h->sc; cfg.nscripts = 1; cfg.v4_only = v4_only;
    cfg.lifetime_ms = 30000;
    int rc = srv_start(&cfg, &h->s);
    if (rc != SRV_OK) { t_skip("server unavailable: %s", srv_strerror(rc)); free(h->steps); free(h); return NULL; }
    return h;
}
hep_srv *hep_start(const srv_step *st, int n) { return hep_start_v4(st, n, 0); }

hep_srv *hep_start_raw(const void *raw, size_t n, int mode) {
    void *copy = malloc(n ? n : 1); memcpy(copy, raw, n);
    srv_step st[6]; memset(st, 0, sizeof st); int k = 0;
    st[k].op = SRV_RECV_HEAD; k++;
    st[k].op = SRV_SEND; st[k].data = (const char *)copy; st[k].n = n; k++;
    if (n == 0) { k--; }   /* nothing to send */
    switch (mode) {
    case 1: st[k++].op = SRV_SHUT_WR; st[k].op = SRV_RECV_BYTES; st[k].n = 0; k++; break;
    case 2: st[k++].op = SRV_RESET; break;
    case 3: st[k].op = SRV_LOOP; st[k].arg = 0; k++; break;
    default: st[k++].op = SRV_CLOSE; break;
    }
    hep_srv *h = hep_start(st, k);
    if (h) h->blob = copy; else free(copy);
    return h;
}
hep_srv *hep_start_raw2(const void *raw, size_t n, const void *raw2, size_t n2) {
    char *copy = (char *)malloc(n + n2 + 1); memcpy(copy, raw, n); memcpy(copy + n, raw2, n2);
    srv_step st[6]; memset(st, 0, sizeof st);
    st[0].op = SRV_RECV_HEAD;
    st[1].op = SRV_SEND; st[1].data = copy; st[1].n = n;
    st[2].op = SRV_RECV_HEAD;
    st[3].op = SRV_SEND; st[3].data = copy + n; st[3].n = n2;
    st[4].op = SRV_CLOSE;
    hep_srv *h = hep_start(st, 5);
    if (h) h->blob = copy; else free(copy);
    return h;
}
hep_srv *hep_start_ok(void) {
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "ok"), S_CLOSE_IF_ASKED(), S_LOOP() };
    return hep_start(st, 5);
}
void hep_stop(hep_srv *h) {
    if (!h) return;
    srv_stop(h->s);
    free(h->blob); free(h->steps); free(h);
}

/* ---------------------------------------------------------------- sessions */
/* Keeper: one extra session handle kept open for the life of the process (see hep_zz_timing_probe and EVIDENCE.md:
 * on the Win10 VM every test cost ~3 s when each test's session was the only open INTERNET handle). */
static HINTERNET g_keeper;
int hep_keeper_on(void) {
    if (!g_keeper && U(InternetOpenA)) g_keeper = U(InternetOpenA)("hep-keeper", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    return g_keeper != NULL;
}
void hep_keeper_off(void) { if (g_keeper) { U(InternetCloseHandle)(g_keeper); g_keeper = NULL; } }
static int g_keeper_auto = 1;
void hep_keeper_auto(int on) { g_keeper_auto = on; }
HINTERNET hep_session(const char *agent, DWORD to) {
    t_net_prepare();
    if (g_keeper_auto) hep_keeper_on();
    return t_inet_open_ex(agent ? agent : "hep", INTERNET_OPEN_TYPE_DIRECT, 0, to ? to : 3000);
}
HINTERNET hep_proxy_session(hep_srv *h, const char *agent) {
    char px[64]; snprintf(px, sizeof px, "http=127.0.0.1:%u", srv_port(h->s));
    t_net_prepare();
    if (g_keeper_auto) hep_keeper_on();
    HINTERNET hi = U(InternetOpenA)(agent ? agent : "hep-proxy", INTERNET_OPEN_TYPE_PROXY, px, "", 0);
    if (hi) {
        DWORD to = 3000;
        U(InternetSetOptionA)(hi, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
        U(InternetSetOptionA)(hi, INTERNET_OPTION_SEND_TIMEOUT, &to, sizeof to);
        U(InternetSetOptionA)(hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
    }
    return hi;
}
HINTERNET hep_connect(HINTERNET hi, hep_srv *h) {
    return U(InternetConnectA)(hi, "127.0.0.1", srv_port(h->s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
}

/* ---------------------------------------------------------------- queries */
static void q_str(HINTERNET hr, DWORD level, const char *name, char *out, size_t cap) {
    char buf[1024]; DWORD l;
    if (name) { snprintf(buf, sizeof buf, "%s", name); l = sizeof buf; }
    else { buf[0] = 0; l = sizeof buf; }
    DWORD idx = 0;
    if (U(HttpQueryInfoA)(hr, level, buf, &l, &idx)) snprintf(out, cap, "%s", hep_esc(buf, l));
    else snprintf(out, cap, "?%lu", GetLastError());
}
static void fill_after_send(HINTERNET hr, const char *qname, hep_res *r) {
    DWORD st = 0, l = sizeof st;
    if (U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL)) r->status = (int)st;
    else { r->status = -1; r->status_qfail = 1; r->status_err = GetLastError(); }
    q_str(hr, HTTP_QUERY_VERSION, NULL, r->ver, sizeof r->ver);
    q_str(hr, HTTP_QUERY_STATUS_TEXT, NULL, r->txt, sizeof r->txt);
    q_str(hr, HTTP_QUERY_CONTENT_LENGTH, NULL, r->cl, sizeof r->cl);
    if (qname) q_str(hr, HTTP_QUERY_CUSTOM, qname, r->hval, sizeof r->hval);
    else r->hval[0] = 0;
}
static void read_body(HINTERNET hr, hep_res *r) {
    r->read_ok = 1; r->nbody = 0; char sink[4096];
    for (int guard = 0; guard < 20000; guard++) {
        DWORD rd = 0; size_t room = sizeof r->body - 1 - (r->nbody < sizeof r->body - 1 ? r->nbody : sizeof r->body - 1);
        char *dst = room ? r->body + r->nbody : sink; DWORD want = room ? (DWORD)room : sizeof sink;
        if (!U(InternetReadFile)(hr, dst, want, &rd)) { r->read_ok = 0; r->read_err = GetLastError(); break; }
        if (!rd) break;
        r->nbody += rd;
        if (r->nbody > (64u << 20)) break;
    }
    size_t k = r->nbody < sizeof r->body - 1 ? r->nbody : sizeof r->body - 1;
    r->body[k] = 0;
}

void hep_do_on(HINTERNET hc, const hep_req *rq, hep_res *r) {
    memset(r, 0, sizeof *r); r->status = -1;
    DWORD t0 = GetTickCount();
    HINTERNET hr = U(HttpOpenRequestA)(hc, rq->verb ? rq->verb : "GET", rq->obj ? rq->obj : "/", rq->ver, NULL, NULL,
                                       rq->flags ? rq->flags : HEP_F, 0);
    if (!hr) { r->ok = FALSE; r->err = GetLastError(); return; }
    SetLastError(0);
    r->ok = U(HttpSendRequestA)(hr, rq->hdrs, rq->hdrs ? (DWORD)-1 : 0, (LPVOID)rq->opt, rq->optlen);
    r->err = r->ok ? 0 : GetLastError();
    if (r->ok) { fill_after_send(hr, rq->qname, r); read_body(hr, r); }
    r->ms = GetTickCount() - t0;
    U(InternetCloseHandle)(hr);
}

void hep_do(hep_srv *h, const hep_req *rq, hep_res *r) {
    HINTERNET hi = hep_session(rq->agent, rq->timeout_ms);
    HINTERNET hc = hi ? U(InternetConnectA)(hi, rq->host ? rq->host : "127.0.0.1", srv_port(h->s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    if (!hc) { memset(r, 0, sizeof *r); r->status = -1; r->err = GetLastError(); t_inet_close(hi); return; }
    hep_do_on(hc, rq, r);
    U(InternetCloseHandle)(hc); t_inet_close(hi);
}

void hep_openurl(HINTERNET hi, const char *url, const char *hdrs, DWORD flags, const char *qname, hep_res *r) {
    memset(r, 0, sizeof *r); r->status = -1;
    DWORD t0 = GetTickCount();
    SetLastError(0);
    HINTERNET hu = U(InternetOpenUrlA)(hi, url, hdrs, hdrs ? (DWORD)-1 : 0, flags ? flags : HEP_F, 0);
    r->ok = hu != NULL; r->err = hu ? 0 : GetLastError();
    if (hu) { fill_after_send(hu, qname, r); read_body(hu, r); U(InternetCloseHandle)(hu); }
    r->ms = GetTickCount() - t0;
}
void hep_openurl_w(HINTERNET hi, const WCHAR *url, DWORD flags, hep_res *r) {
    memset(r, 0, sizeof *r); r->status = -1;
    SetLastError(0);
    HINTERNET hu = U(InternetOpenUrlW)(hi, url, NULL, 0, flags ? flags : HEP_F, 0);
    r->ok = hu != NULL; r->err = hu ? 0 : GetLastError();
    if (hu) { fill_after_send(hu, NULL, r); read_body(hu, r); U(InternetCloseHandle)(hu); }
}

/* ---------------------------------------------------------------- signatures */
const char *hep_esc(const void *pv, size_t n) {
    static char b[8][1600]; static volatile LONG k;
    char *o = b[InterlockedIncrement(&k) & 7]; size_t j = 0;
    const unsigned char *p = (const unsigned char *)pv;
    for (size_t i = 0; i < n && j < 1500; i++) {
        unsigned c = p[i];
        if (c == '\r') { o[j++] = '\\'; o[j++] = 'r'; }
        else if (c == '\n') { o[j++] = '\\'; o[j++] = 'n'; }
        else if (c == '\t') { o[j++] = '\\'; o[j++] = 't'; }
        else if (c == '\\') { o[j++] = '\\'; o[j++] = '\\'; }
        else if (c < 0x20 || c >= 0x7f) j += snprintf(o + j, 1600 - j, "\\x%02x", c);
        else o[j++] = (char)c;
    }
    o[j] = 0;
    return o;
}

const char *hep_sig(const hep_res *r, unsigned what) {
    static char b[8][2400]; static volatile LONG k;
    char *o = b[InterlockedIncrement(&k) & 7]; size_t j = 0;
    if (!r->ok) { snprintf(o, 2400, "ok=0 err=%lu", r->err); return o; }
    if (r->status_qfail) j += snprintf(o + j, 2400 - j, "ok=1 st=");
    else j += snprintf(o + j, 2400 - j, "ok=1 st=%lu", (unsigned long)(DWORD)r->status);
    if (r->status_qfail) j += snprintf(o + j, 2400 - j, "?%lu", r->status_err);
    if (what & 1) j += snprintf(o + j, 2400 - j, " ver=%s", r->ver);
    if (what & 2) j += snprintf(o + j, 2400 - j, " txt=%s", r->txt);
    if (what & 4) j += snprintf(o + j, 2400 - j, " h=%s", r->hval);
    if (what & 8) j += snprintf(o + j, 2400 - j, " cl=%s", r->cl);
    if (!r->read_ok) j += snprintf(o + j, 2400 - j, " rerr=%lu", r->read_err);
    size_t show = r->nbody < 48 ? r->nbody : 48;
    j += snprintf(o + j, 2400 - j, " n=%zu body=%s", r->nbody, hep_esc(r->body, show));
    return o;
}

void hep_expect_sig(const char *tag, const char *got, const char *want, const char *file, int line) {
    if (!want) { t_note("OBS %s | %s", tag, got); return; }
    t_check(strcmp(got, want) == 0, file, line, tag, "signature\n      got:  %s\n      want: %s", got, want);
}

typedef struct { hep_srv *h; hep_req rq; hep_res r; } rc_ctx;
static DWORD WINAPI rc_thread(void *p) { rc_ctx *c = (rc_ctx *)p; hep_do(c->h, &c->rq, &c->r); return 0; }

void hep_rcase(const char *tag, const char *raw, size_t n, int mode, const char *qname, unsigned what, const char *want) {
    hep_srv *h = hep_start_raw(raw, n, mode);
    if (!h) return;
    rc_ctx *c = (rc_ctx *)calloc(1, sizeof *c);
    c->h = h; c->rq.qname = qname; c->rq.obj = "/edge";
    DWORD t0 = GetTickCount();
    HANDLE th = CreateThread(NULL, 0, rc_thread, c, 0, NULL);
    DWORD w = WaitForSingleObject(th, 20000);
    CloseHandle(th);
    if (w != WAIT_OBJECT_0) { t_check(0, __FILE__, __LINE__, tag, "request hung > 20 s"); return; /* leak c, h */ }
    EXPECT_SIG(tag, hep_sig(&c->r, what), want);
    DWORD t1 = GetTickCount();
    hep_stop(h);
    DWORD t2 = GetTickCount();
    if (t2 - t0 > 1500) t_note("timing: %s request+session %lu ms (send+read %lu), server stop %lu ms", tag, t1 - t0, c->r.ms, t2 - t1);
    free(c);
}

/* ---------------------------------------------------------------- recorder helpers */
const char *hep_names(srv *s, int i) {
    static char b[8][4096]; static volatile LONG k;
    char *o = b[InterlockedIncrement(&k) & 7]; size_t n = 0; o[0] = 0;
    int c = srv_req_header_count(s, i);
    for (int h = 0; h < c && n < 4000; h++) {
        const char *nm = srv_req_header_name(s, i, h);
        n += snprintf(o + n, 4096 - n, "%s%s", h ? "|" : "", nm ? nm : "?");
    }
    return o;
}
const char *hep_raw(srv *s, int i) {
    size_t n = 0; const char *r = srv_req_head_raw(s, i, &n);
    if (!r) return "(none)";
    return hep_esc(r, n);
}
const char *hep_hostport(hep_srv *h) {
    static char b[4][64]; static volatile LONG k; char *o = b[InterlockedIncrement(&k) & 3];
    snprintf(o, 64, "127.0.0.1:%u", srv_port(h->s)); return o;
}
void hep_dump(srv *s, int i) { t_note("req %d conn %d: %s", i, srv_req_conn(s, i), hep_raw(s, i)); }

static DWORD WINAPI guard_thread(void *p) { ((void (*)(void))p)(); return 0; }
int hep_guard(const char *name, void (*fn)(void), DWORD ms) {
    if (g_keeper_auto) hep_keeper_on();
    HANDLE th = CreateThread(NULL, 0, guard_thread, (void *)fn, 0, NULL);
    if (!th) { fn(); return 1; }
    DWORD t0 = GetTickCount();
    DWORD r = WaitForSingleObject(th, ms);
    CloseHandle(th);
    if (GetTickCount() - t0 > 8000) t_note("timing: %s took %lu ms", name, GetTickCount() - t0);
    t_check(r == WAIT_OBJECT_0, __FILE__, __LINE__, "guarded test finished", "%s still running after %lu ms (hang)", name, ms);
    return r == WAIT_OBJECT_0;
}

/* ---------------------------------------------------------------- timing probe (runs first: last registered) */
static void probe_round(const char *label, int n) {
    DWORD tot_open = 0, tot_req = 0, tot_close = 0, tot_stop = 0;
    for (int i = 0; i < n; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        DWORD a = GetTickCount();
        HINTERNET hi = t_inet_open_ex("hep-probe", INTERNET_OPEN_TYPE_DIRECT, 0, 3000);
        HINTERNET hc = hep_connect(hi, h);
        DWORD b = GetTickCount();
        hep_req rq = {0}; hep_res r; hep_do_on(hc, &rq, &r);
        DWORD c = GetTickCount();
        U(InternetCloseHandle)(hc); t_inet_close(hi);
        DWORD d = GetTickCount();
        hep_stop(h);
        DWORD e = GetTickCount();
        tot_open += b - a; tot_req += c - b; tot_close += d - c; tot_stop += e - d;
        CHECK(r.ok && r.status == 200);
    }
    t_note("timing probe %s (%d rounds): open %lu ms, request %lu ms, close %lu ms, server stop %lu ms", label, n, tot_open, tot_req, tot_close, tot_stop);
}
TEST(hep_zz_timing_probe) {
    /* measures where per-test time goes with and without a long-lived extra session handle; never fails on timing */
    HEP_REQUIRE_HTTP();
    t_net_prepare();
    hep_keeper_auto(0); hep_keeper_off();
    probe_round("no keeper", 4);
    hep_keeper_on();
    probe_round("keeper", 4);
    hep_keeper_auto(1);
}
