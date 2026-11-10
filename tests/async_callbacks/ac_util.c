/* ac_util.c - status-callback recorder and async helpers for the async_callbacks area. See ac.h. */
#include "ac.h"

static CRITICAL_SECTION g_cs;
static int g_cs_init;
static ac_ev g_ev[AC_MAXEV];
static volatile LONG g_n, g_dropped, g_cb2;
static HANDLE g_any;           /* auto-reset, set on every event */
volatile ac_hook_fn ac_hook;
DWORD ac_main_tid;

static void lock(void) { if (!g_cs_init) { InitializeCriticalSection(&g_cs); g_cs_init = 1; g_any = CreateEventA(NULL, FALSE, FALSE, NULL); } EnterCriticalSection(&g_cs); }
static void unlock(void) { LeaveCriticalSection(&g_cs); }

static void record(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len, int wide) {
    lock();
    if (g_n < AC_MAXEV) {
        ac_ev *e = &g_ev[g_n];
        memset(e, 0, sizeof *e);
        e->h = h; e->ctx = ctx; e->st = st; e->len = len; e->has_info = info != NULL; e->tid = GetCurrentThreadId();
        e->wide = wide; e->seq = (DWORD)g_n;
        if (info) {
            /* the length of string statuses is not always the buffer size; copy min(len, AC_INFO) only. */
            DWORD c = len < AC_INFO ? len : AC_INFO;
            /* the W callback gets RESOLVING_NAME / REDIRECT converted to UTF-16 with the length still in characters
             * (observed: len 27 for a 27-char URL); copy the whole wide string */
            if (wide == 1 && (st == INTERNET_STATUS_RESOLVING_NAME || st == INTERNET_STATUS_REDIRECT)) {
                c = 0; const WCHAR *w = (const WCHAR *)info;
                while (c + 2 < AC_INFO && w[c / 2]) c += 2;
            }
            memcpy(e->info, info, c);
        }
        g_n++;
    } else g_dropped++;
    unlock();
    SetEvent(g_any);
    ac_hook_fn hk = ac_hook;
    if (hk) hk(h, ctx, st, info, len);
}
void CALLBACK ac_cb(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) { record(h, ctx, st, info, len, 0); }
void CALLBACK ac_cbw(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) { record(h, ctx, st, info, len, 1); }
void CALLBACK ac_cb2(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) { InterlockedIncrement(&g_cb2); record(h, ctx, st, info, len, 2); }

void ac_begin(void) {
    lock(); g_n = 0; g_dropped = 0; g_cb2 = 0; ac_hook = NULL; ResetEvent(g_any); unlock();
    ac_main_tid = GetCurrentThreadId();
    t_net_prepare();
}
int ac_count(void) { lock(); int n = g_n; unlock(); return n; }
int ac_count_cb2(void) { return (int)g_cb2; }
int ac_get(int i, ac_ev *out) { lock(); int ok = i >= 0 && i < g_n; if (ok) *out = g_ev[i]; unlock(); return ok; }
int ac_count_st_ctx(DWORD st, DWORD_PTR ctx) {
    lock(); int c = 0; for (int i = 0; i < g_n; i++) if (g_ev[i].st == st && (!ctx || g_ev[i].ctx == ctx)) c++; unlock(); return c;
}
int ac_count_st(DWORD st) { return ac_count_st_ctx(st, 0); }
int ac_find(DWORD st, DWORD_PTR ctx, int from) {
    lock(); int r = -1; for (int i = from < 0 ? 0 : from; i < g_n; i++) if (g_ev[i].st == st && (!ctx || g_ev[i].ctx == ctx)) { r = i; break; } unlock(); return r;
}
int ac_find_h(DWORD st, HINTERNET h, int from) {
    lock(); int r = -1; for (int i = from < 0 ? 0 : from; i < g_n; i++) if (g_ev[i].st == st && g_ev[i].h == h) { r = i; break; } unlock(); return r;
}
int ac_wait_st(DWORD st, DWORD_PTR ctx, int n, DWORD ms) {
    DWORD t0 = GetTickCount();
    for (;;) {
        if (ac_count_st_ctx(st, ctx) >= n) return 1;
        DWORD el = GetTickCount() - t0; if (el >= ms) return 0;
        WaitForSingleObject(g_any, ms - el < 50 ? ms - el : 50);
    }
}
int ac_wait_complete(DWORD_PTR ctx, int k, DWORD ms, INTERNET_ASYNC_RESULT *res) {
    if (res) memset(res, 0, sizeof *res);
    if (!ac_wait_st(INTERNET_STATUS_REQUEST_COMPLETE, ctx, k, ms)) return 0;
    int idx = -1;
    for (int i = 0, seen = 0; ; i = idx + 1) { idx = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, ctx, i); if (idx < 0) return 0; if (++seen == k) break; }
    ac_ev e; ac_get(idx, &e);
    if (res && e.has_info && e.len >= sizeof(INTERNET_ASYNC_RESULT)) memcpy(res, e.info, sizeof *res);
    return 1;
}
static const char *seq_impl(DWORD_PTR ctx, int from, int to, const DWORD *skip) {
    static char buf[4][2048]; static int rot; char *o = buf[rot++ & 3]; size_t n = 0; o[0] = 0;
    lock();
    if (to < 0 || to > g_n) to = g_n;
    for (int i = from < 0 ? 0 : from; i < to; i++) {
        if (ctx && g_ev[i].ctx != ctx) continue;
        int sk = 0; for (const DWORD *p = skip; p && *p; p++) if (*p == g_ev[i].st) sk = 1;
        if (sk) continue;
        if (n + 12 < sizeof buf[0]) n += snprintf(o + n, sizeof buf[0] - n, "%s%lu", n ? "," : "", g_ev[i].st);
    }
    unlock();
    return o;
}
const char *ac_seq(DWORD_PTR ctx, const DWORD *skip) { return seq_impl(ctx, 0, -1, skip); }
const char *ac_seq_range(DWORD_PTR ctx, int from, int to, const DWORD *skip) { return seq_impl(ctx, from, to, skip); }
DWORD ac_info_dword(const ac_ev *e) { DWORD d = 0; if (e->has_info && e->len >= 4) memcpy(&d, e->info, 4); return d; }
DWORD_PTR ac_info_ptr(const ac_ev *e) { DWORD_PTR d = 0; if (e->has_info && e->len >= sizeof d) memcpy(&d, e->info, sizeof d); return d; }

void ac_dump(const char *tag) {
    int n = ac_count();
    t_note("%s: %d events (main tid %lu, dropped %ld)", tag, n, ac_main_tid, g_dropped);
    for (int i = 0; i < n; i++) {
        ac_ev e; ac_get(i, &e);
        char hex[3 * 24 + 1] = "", txt[AC_INFO + 1] = "";
        DWORD c = e.len < 24 ? e.len : 24; if (!e.has_info) c = 0;
        for (DWORD k = 0; k < c; k++) snprintf(hex + 3 * k, 4, "%02x ", e.info[k]);
        DWORD tc = e.len < AC_INFO ? e.len : AC_INFO; if (!e.has_info) tc = 0;
        for (DWORD k = 0; k < tc; k++) { unsigned char ch = e.info[k]; txt[k] = (ch >= 32 && ch < 127) ? ch : '.'; } txt[tc] = 0;
        t_note("  [%d] st=%lu ctx=%llx h=%p len=%lu info=%d %s tid=%s%s [%s] '%s'", i, e.st, (unsigned long long)e.ctx, e.h, e.len, e.has_info,
               e.wide == 1 ? "W" : e.wide == 2 ? "cb2" : "A", e.tid == ac_main_tid ? "main" : "other", "", hex, txt);
    }
}
int ac_before(DWORD a, DWORD b, DWORD_PTR ctx) { int ia = ac_find(a, ctx, 0), ib = ac_find(b, ctx, 0); return ia >= 0 && ib >= 0 && ia < ib; }
int ac_count_not_tid(DWORD_PTR ctx, DWORD tid) {
    lock(); int c = 0; for (int i = 0; i < g_n; i++) if ((!ctx || g_ev[i].ctx == ctx) && g_ev[i].tid != tid) c++; unlock(); return c;
}
int ac_count_tid(DWORD_PTR ctx, DWORD tid) {
    lock(); int c = 0; for (int i = 0; i < g_n; i++) if ((!ctx || g_ev[i].ctx == ctx) && g_ev[i].tid == tid) c++; unlock(); return c;
}

HINTERNET ac_open(DWORD flags) {
    t_net_prepare();
    return (HINTERNET)t_inet_open_ex("ac-agent", INTERNET_OPEN_TYPE_DIRECT, flags, 5000);
}
HINTERNET ac_open_cb(DWORD flags, INTERNET_STATUS_CALLBACK cb) {
    HINTERNET h = ac_open(flags);
    if (h) U(InternetSetStatusCallbackA)(h, cb);
    return h;
}
void ac_close_wait(HINTERNET h, DWORD_PTR ctx) {
    if (!h) return;
    int before = ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, ctx);
    U(InternetCloseHandle)(h);
    if (ctx) ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, ctx, before + 1, 2000);
}
void ac_quiesce(DWORD quiet_ms, DWORD max_ms) {
    DWORD t0 = GetTickCount(); int last = ac_count(); DWORD tl = GetTickCount();
    while (GetTickCount() - t0 < max_ms) {
        Sleep(20);
        int n = ac_count(); if (n != last) { last = n; tl = GetTickCount(); }
        else if (GetTickCount() - tl >= quiet_ms) break;
    }
}

int ac_send_wait(HINTERNET hreq, DWORD_PTR ctx, const char *hdrs, void *opt, DWORD optn, int *pending, DWORD *err) {
    int before = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, ctx);
    if (pending) *pending = 0; if (err) *err = 0;
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpSendRequestA)(hreq, hdrs, hdrs ? (DWORD)-1 : 0, opt, optn);
    if (ok) return 1;
    DWORD e = GetLastError();
    if (e != ERROR_IO_PENDING) { if (err) *err = e; return 0; }
    if (pending) *pending = 1;
    INTERNET_ASYNC_RESULT r;
    if (!ac_wait_complete(ctx, before + 1, 8000, &r)) { if (err) *err = WAIT_TIMEOUT; return 0; }
    if (!r.dwResult) { if (err) *err = r.dwError; return 0; }
    return 1;
}

long ac_read_all_async(HINTERNET hreq, DWORD_PTR ctx, char *buf, size_t cap, int *npending) {
    static char chunk[8192]; static DWORD rd;
    long total = 0; if (npending) *npending = 0;
    for (int guard = 0; guard < 4096; guard++) {
        int before = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, ctx);
        rd = 0xdeadbeef;
        BOOL ok = U(InternetReadFile)(hreq, chunk, sizeof chunk, &rd);
        if (!ok) {
            if (GetLastError() != ERROR_IO_PENDING) return -1;
            if (npending) (*npending)++;
            INTERNET_ASYNC_RESULT r;
            if (!ac_wait_complete(ctx, before + 1, 8000, &r) || !r.dwResult) return -1;
        }
        if (rd == 0) break;
        if (rd > sizeof chunk) return -1;
        if (buf && (size_t)total + rd < cap) memcpy(buf + total, chunk, rd);
        total += rd;
    }
    if (buf && cap) buf[(size_t)total < cap ? (size_t)total : cap - 1] = 0;
    return total;
}

DWORD ac_status_code(HINTERNET hreq) {
    DWORD st = 0, l = sizeof st;
    if (!U(HttpQueryInfoA)(hreq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL)) return 0;
    return st;
}

int ac_flow_open(ac_flow *f, const srv_step *steps, int nsteps, DWORD sflags, INTERNET_STATUS_CALLBACK cb,
                 const char *verb, const char *path, DWORD rflags) {
    memset(f, 0, sizeof *f);
    f->sflags = sflags;
    f->s = srv_http(steps, nsteps);
    if (!f->s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return 0; }
    f->hi = ac_open(sflags);
    if (!f->hi) { t_check(0, __FILE__, __LINE__, "InternetOpen", "err %lu", GetLastError()); srv_stop(f->s); f->s = NULL; return 0; }
    if (cb) U(InternetSetStatusCallbackA)(f->hi, cb);
    f->hc = U(InternetConnectA)(f->hi, "127.0.0.1", srv_port(f->s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_CON);
    if (f->hc) f->hr = U(HttpOpenRequestA)(f->hc, verb, path, NULL, NULL, NULL, rflags, CTX_REQ);
    if (!f->hc || !f->hr) { t_check(0, __FILE__, __LINE__, "connect/open request", "err %lu", GetLastError()); ac_flow_close(f); return 0; }
    return 1;
}
void ac_flow_close(ac_flow *f) {
    int cb = 0;
    if (f->hi) { void *p = NULL; DWORD l = sizeof p; if (U(InternetQueryOptionA)(f->hi, INTERNET_OPTION_CALLBACK, &p, &l) && p) cb = 1; }
    if (f->hr) { if (cb) ac_close_wait(f->hr, CTX_REQ); else U(InternetCloseHandle)(f->hr); f->hr = NULL; }
    if (f->hc) { if (cb) ac_close_wait(f->hc, CTX_CON); else U(InternetCloseHandle)(f->hc); f->hc = NULL; }
    if (f->hi) { U(InternetSetStatusCallbackA)(f->hi, NULL); U(InternetCloseHandle)(f->hi); f->hi = NULL; }
    if (f->s) { srv_stop(f->s); f->s = NULL; }
}
