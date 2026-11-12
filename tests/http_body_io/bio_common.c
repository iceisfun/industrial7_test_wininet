/* bio_common.c - helpers for the http_body_io area (see bio.h). Not a test file: no TEST() here. */
#include "bio.h"
#include <wincrypt.h>
#include <stdlib.h>

/* Copy every script with a bio_wait_next step inserted before each step that reads a request (SRV_RECV_HEAD and the
 * area's SRV_CALL responders, which all start with srv_conn_recv_head); SRV_LOOP targets are remapped. */
static int is_reader(const srv_step *p) { return p->op == SRV_RECV_HEAD || (p->op == SRV_CALL && p->fn != bio_wait_next); }
static void *wrap_scripts(const srv_config *cfg, srv_config *out) {
    *out = *cfg;
    if (!cfg->scripts || cfg->nscripts <= 0) return NULL;
    int ns = cfg->nscripts, total = 0;
    int *len = calloc(ns, sizeof *len);
    for (int k = 0; k < ns; k++) {
        int n = cfg->scripts[k].nsteps;
        if (n <= 0) { n = 0; while (cfg->scripts[k].steps[n].op != SRV_END) n++; n++; }
        len[k] = n; total += 2 * n;
    }
    char *mem = calloc(1, ns * sizeof(srv_script) + total * sizeof(srv_step));
    srv_script *sc = (srv_script *)mem; srv_step *pool = (srv_step *)(mem + ns * sizeof(srv_script));
    for (int k = 0; k < ns; k++) {
        const srv_step *in = cfg->scripts[k].steps; int n = len[k], m = 0;
        srv_step *o = pool;
        for (int i = 0; i < n; i++) {
            if (is_reader(&in[i])) { srv_step w = S_CALL(bio_wait_next); o[m++] = w; }
            o[m] = in[i];
            if (in[i].op == SRV_LOOP) {
                int j = in[i].arg, before = 0;
                for (int q = 0; q < j && q < n; q++) before += is_reader(&in[q]);
                o[m].arg = j + before;
            }
            m++;
        }
        sc[k].steps = o; sc[k].nsteps = m; pool += m;
    }
    free(len);
    out->scripts = sc;
    return mem;
}

static int open_cfg_dec(bio_env *e, const srv_config *cfg0, int dec) {
    memset(e, 0, sizeof *e);
    if (!U(InternetOpenA) || !U(InternetConnectA) || !U(HttpOpenRequestA) || !U(HttpSendRequestA) || !U(InternetReadFile)) {
        t_skip("wininet exports missing"); return 0;
    }
    srv_config cfg; e->owned = wrap_scripts(cfg0, &cfg);
    int rc = srv_start(&cfg, &e->s);
    if (rc) { e->s = NULL; free(e->owned); e->owned = NULL; t_skip("server unavailable: %s", srv_strerror(rc)); return 0; }
    e->t0 = GetTickCount();
    e->hi = t_inet_open("bio-agent/1.0");
    if (!e->hi) { srv_stop(e->s); e->s = NULL; t_skip("InternetOpenA failed %lu", GetLastError()); return 0; }
    if (dec) CHECK(bio_set_dword(e->hi, INTERNET_OPTION_HTTP_DECODING, TRUE));
    e->hc = U(InternetConnectA)(e->hi, "127.0.0.1", srv_port(e->s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!e->hc) { DWORD er = GetLastError(); t_inet_close(e->hi); srv_stop(e->s); e->s = NULL; e->hi = NULL; t_skip("InternetConnectA failed %lu", er); return 0; }
    return 1;
}
int bio_open_cfg(bio_env *e, const srv_config *cfg) { return open_cfg_dec(e, cfg, 0); }

static int open_steps(bio_env *e, const srv_step *st, int n, int dec) {
    srv_script sc = { st, n };
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTP; cfg.scripts = st ? &sc : NULL; cfg.nscripts = st ? 1 : 0; cfg.lifetime_ms = 30000;
    return open_cfg_dec(e, &cfg, dec);            /* the steps are copied: the caller's array may be on its stack */
}
int bio_open(bio_env *e, const srv_step *st, int n) { return open_steps(e, st, n, 0); }
int bio_open_dec(bio_env *e, const srv_step *st, int n, int dec) { return open_steps(e, st, n, dec); }

/* InternetCloseHandle on a worker thread with an outer bound: a close that blocks is reported, never hangs the area */
static DWORD WINAPI close_thread(LPVOID p) { U(InternetCloseHandle)((HINTERNET)p); return 0; }
static int close_bounded(HINTERNET h, const char *what) {
    if (!h) return 1;
    DWORD t0 = GetTickCount();
    HANDLE th = CreateThread(NULL, 0, close_thread, h, 0, NULL);
    if (!th) { U(InternetCloseHandle)(h); return 1; }
    DWORD w = WaitForSingleObject(th, 10000);
    CloseHandle(th);
    DWORD dt = GetTickCount() - t0;
    if (w != WAIT_OBJECT_0) { CHECKF(0, "InternetCloseHandle(%s) still blocked after %lu ms", what, dt); return 0; }
    if (dt > 1000) t_note("InternetCloseHandle(%s) took %lu ms", what, dt);
    return 1;
}
void bio_h(HINTERNET h) { close_bounded(h, "request"); }

void bio_close(bio_env *e) {
    int ok = close_bounded(e->hc, "connect") & close_bounded(e->hi, "session");
    e->hc = e->hi = NULL;
    DWORD dt = GetTickCount() - e->t0;
    if (dt > 3000) t_note("test body took %lu ms", dt);
    if (e->s) srv_stop(e->s);
    (void)ok;
    e->s = NULL;
    free(e->owned); e->owned = NULL;
}

HINTERNET bio_req(bio_env *e, const char *verb, const char *path, DWORD extra, const char *hdrs, BOOL *ok, DWORD *err) {
    HINTERNET hr = U(HttpOpenRequestA)(e->hc, verb, path, NULL, NULL, NULL, T_INET_FRESH | extra, 0);
    if (ok) *ok = FALSE;
    if (err) *err = hr ? 0 : GetLastError();
    if (!hr) return NULL;
    SetLastError(0);
    BOOL r = U(HttpSendRequestA)(hr, hdrs, hdrs ? (DWORD)-1 : 0, NULL, 0);
    if (ok) *ok = r;
    if (err) *err = r ? 0 : GetLastError();
    return hr;
}

HINTERNET bio_get(bio_env *e, const char *path) {
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(e, "GET", path, 0, NULL, &ok, &err);
    CHECKF(hr && ok, "GET %s: send failed err=%lu %s", path, err, t_inet_errname(err));
    return hr;
}

size_t bio_read(HINTERNET h, void *buf, size_t cap, DWORD piece, bio_rd *r) {
    bio_rd z; if (!r) r = &z; memset(r, 0, sizeof *r);
    if (!piece) piece = 65536;
    unsigned char *b = buf; static unsigned char sink[65536];
    for (int guard = 0; guard < 4000000; guard++) {
        DWORD rd = 0xDEADBEEF; unsigned char *dst; DWORD want = piece;
        if (r->n < cap) { dst = b + r->n; if (want > cap - r->n) want = (DWORD)(cap - r->n); }
        else { dst = sink; if (want > sizeof sink) want = sizeof sink; }
        SetLastError(0xBEEF);
        if (!U(InternetReadFile)(h, dst, want, &rd)) { r->ok = 0; r->err = GetLastError(); return r->n; }
        if (rd == 0xDEADBEEF) { r->ok = 0; r->err = 0xDEADBEEF; return r->n; }
        if (rd > want) r->over++;
        if (!rd) { r->ok = 1; return r->n; }
        r->calls++; if (rd > r->maxrd) r->maxrd = rd;
        r->n += rd;
    }
    r->ok = 0; r->err = 0xDEAD0002; return r->n;
}

size_t bio_read_ex(HINTERNET h, void *buf, size_t cap, DWORD piece, DWORD flags, bio_rd *r) {
    bio_rd z; if (!r) r = &z; memset(r, 0, sizeof *r);
    if (!piece) piece = 65536;
    unsigned char *b = buf; static unsigned char sink[65536];
    for (int guard = 0; guard < 4000000; guard++) {
        INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib;
        DWORD want = piece;
        if (r->n < cap) { ib.lpvBuffer = b + r->n; if (want > cap - r->n) want = (DWORD)(cap - r->n); }
        else { ib.lpvBuffer = sink; if (want > sizeof sink) want = sizeof sink; }
        ib.dwBufferLength = want;
        if (!U(InternetReadFileExA)(h, &ib, flags, 0)) { r->ok = 0; r->err = GetLastError(); return r->n; }
        if (ib.dwBufferLength > want) r->over++;
        if (!ib.dwBufferLength) { r->ok = 1; return r->n; }
        r->calls++; if (ib.dwBufferLength > r->maxrd) r->maxrd = ib.dwBufferLength;
        r->n += ib.dwBufferLength;
    }
    r->ok = 0; r->err = 0xDEAD0002; return r->n;
}

DWORD bio_status(HINTERNET h) {
    DWORD st = 0, l = sizeof st;
    if (!U(HttpQueryInfoA)(h, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL)) return 0;
    return st;
}

const char *bio_hdr(HINTERNET h, DWORD q, char *buf, DWORD cap, DWORD *err) {
    DWORD l = cap; buf[0] = 0;
    if (!U(HttpQueryInfoA)(h, q, buf, &l, NULL)) { if (err) *err = GetLastError(); return NULL; }
    if (err) *err = 0;
    return buf;
}

const char *bio_custom(HINTERNET h, const char *name, char *buf, DWORD cap, DWORD *err) {
    lstrcpynA(buf, name, (int)cap);
    DWORD l = cap;
    if (!U(HttpQueryInfoA)(h, HTTP_QUERY_CUSTOM, buf, &l, NULL)) { if (err) *err = GetLastError(); buf[0] = 0; return NULL; }
    if (err) *err = 0;
    return buf;
}

DWORD bio_qda(HINTERNET h, DWORD *err) {
    DWORD n = 0xDEADBEEF;
    if (!U(InternetQueryDataAvailable)(h, &n, 0, 0)) { if (err) *err = GetLastError(); return (DWORD)-1; }
    if (err) *err = 0;
    return n;
}

int bio_set_dword(HINTERNET h, DWORD opt, DWORD v) { return U(InternetSetOptionA)(h, opt, &v, sizeof v); }

HINTERNET bio_https_get(HINTERNET hc, const char *path, int req_decoding, const char *hdrs, BOOL *ok, DWORD *err) {
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
    if (!hr) { *ok = FALSE; *err = GetLastError(); return NULL; }
    if (req_decoding) CHECK(bio_set_dword(hr, INTERNET_OPTION_HTTP_DECODING, TRUE));
    t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    *ok = U(HttpSendRequestA)(hr, hdrs, hdrs ? (DWORD)-1 : 0, NULL, 0); *err = *ok ? 0 : GetLastError();
    return hr;
}

unsigned char *bio_pattern(size_t n) {
    unsigned char *p = malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++) p[i] = srv_pattern_byte(i);
    return p;
}

int bio_sha256(const void *p, size_t n, unsigned char out[32]) {
    HCRYPTPROV prov; HCRYPTHASH hh; int ok = 0;
    if (!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return 0;
    if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hh)) {
        DWORD l = 32;
        if (CryptHashData(hh, p, (DWORD)n, 0) && CryptGetHashParam(hh, HP_HASHVAL, out, &l, 0) && l == 32) ok = 1;
        CryptDestroyHash(hh);
    }
    CryptReleaseContext(prov, 0);
    return ok;
}
