/* options_table fixture: one handle of every kind (see ot.h), loopback servers only. */
#include "ot.h"

BOOL ot_q(int w, HINTERNET h, DWORD opt, void *buf, DWORD *len) {
    return w ? U(InternetQueryOptionW)(h, opt, buf, len) : U(InternetQueryOptionA)(h, opt, buf, len);
}
BOOL ot_s(int w, HINTERNET h, DWORD opt, void *buf, DWORD len) {
    return w ? U(InternetSetOptionW)(h, opt, buf, len) : U(InternetSetOptionA)(h, opt, buf, len);
}
BOOL ot_qdw(HINTERNET h, DWORD opt, DWORD *v) {
    DWORD l = sizeof *v; *v = 0xDEADBEEF;
    BOOL r = U(InternetQueryOptionA)(h, opt, v, &l);
    return r && l == 4;
}
BOOL ot_sdw(HINTERNET h, DWORD opt, DWORD v) { return U(InternetSetOptionA)(h, opt, &v, sizeof v); }

const char *ot_hex(const void *p, DWORD n) {
    static char b[4][200]; static int k; char *o = b[k++ & 3]; const unsigned char *u = p;
    if (n > 96) n = 96;
    for (DWORD i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", u[i]);
    o[2 * n] = 0;
    return o;
}

static HINTERNET send_get(HINTERNET hc, const char *path, DWORD flags, int tls) {
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, flags, 0);
    if (!hr) return NULL;
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    for (int k = 0; tls && !ok && k < 3; k++) {          /* 1st: 12045 INVALID_CA (SRV.md F8), then OR the ignore flag */
        t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
        ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    }
    if (!ok) { t_note("ot fixture: send %s failed %lu", path, GetLastError()); U(InternetCloseHandle)(hr); return NULL; }
    char b[64]; t_inet_read_all(hr, b, sizeof b, NULL);
    return hr;
}

ot_fx *ot_fx_open(unsigned mask) {
    if (!U(InternetOpenA) || !U(InternetQueryOptionA)) return NULL;
    ot_fx *fx = calloc(1, sizeof *fx);
    fx->h[OT_S] = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!fx->h[OT_S]) { free(fx); return NULL; }
    if (mask & (OT_BIT(OT_C) | OT_BIT(OT_R) | OT_BIT(OT_X))) {
        srv_config cfg = { SRV_HTTP }; cfg.lifetime_ms = 120000;
        if (!srv_start(&cfg, &fx->http)) {
            fx->h[OT_C] = U(InternetConnectA)(fx->h[OT_S], "127.0.0.1", srv_port(fx->http), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
            if (fx->h[OT_C] && (mask & OT_BIT(OT_R))) fx->h[OT_R] = U(HttpOpenRequestA)(fx->h[OT_C], "GET", "/p", NULL, NULL, NULL, T_INET_FRESH, 0);
            if (fx->h[OT_C] && (mask & OT_BIT(OT_X))) fx->h[OT_X] = send_get(fx->h[OT_C], "/x", T_INET_FRESH, 0);
            snprintf(fx->url_x, sizeof fx->url_x, "%s", srv_url(fx->http, "/x"));
            snprintf(fx->url_r, sizeof fx->url_r, "%s", srv_url(fx->http, "/p"));
        }
    }
    if (mask & OT_BIT(OT_T)) {
        srv_config cfg = { SRV_HTTPS }; cfg.lifetime_ms = 120000; cfg.cert_profile = SRV_CERT_LOCALHOST;
        if (!srv_start(&cfg, &fx->https)) {
            HINTERNET hc = U(InternetConnectA)(fx->h[OT_S], "127.0.0.1", srv_port(fx->https), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
            if (hc) fx->h[OT_T] = send_get(hc, "/t", T_INET_FRESH | INTERNET_FLAG_SECURE, 1);
            fx->has_tls = fx->h[OT_T] != NULL;
            snprintf(fx->url_t, sizeof fx->url_t, "%s", srv_url(fx->https, "/t"));
        }
    }
    if (mask & OT_BIT(OT_F)) {
        static const srv_ftp_file files[] = { { "/hello.txt", "hello", 5, "20200102030405" } };
        static const srv_ftp_config fc = { files, 1 };
        srv_config cfg = { SRV_FTP }; cfg.ftp = &fc; cfg.lifetime_ms = 120000;
        if (!srv_start(&cfg, &fx->ftp))
            fx->h[OT_F] = U(InternetConnectA)(fx->h[OT_S], "127.0.0.1", srv_port(fx->ftp), "anonymous", "x@y", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
        if (!fx->h[OT_F]) t_note("ot fixture: FTP connect failed %lu", GetLastError());
    }
    if (mask & OT_BIT(OT_L)) {
        char url[MAX_PATH + 16];
        t_tmpfile(fx->file_path, sizeof fx->file_path, "ot_file.txt");
        FILE *f = fopen(fx->file_path, "wb"); if (f) { fputs("filedata", f); fclose(f); }
        snprintf(url, sizeof url, "file://%s", fx->file_path);
        fx->h[OT_L] = U(InternetOpenUrlA)(fx->h[OT_S], url, NULL, 0, 0, 0);
        if (!fx->h[OT_L]) t_note("ot fixture: file:// open failed %lu", GetLastError());
    }
    return fx;
}

void ot_fx_close(ot_fx *fx) {
    if (!fx) return;
    for (int k = OT_NK - 1; k > OT_N; k--) if (fx->h[k] && k != OT_S) U(InternetCloseHandle)(fx->h[k]);
    if (fx->h[OT_S]) U(InternetCloseHandle)(fx->h[OT_S]);   /* closes the HTTPS connect handle too */
    srv_stop(fx->http); srv_stop(fx->https); srv_stop(fx->ftp);
    free(fx);
}

static ot_fx *g_all;
static void close_all(void) { ot_fx *f = g_all; g_all = NULL; ot_fx_close(f); }
ot_fx *ot_fx_all(void) {
    if (!g_all) { g_all = ot_fx_open(OT_MASK_ALL); if (g_all) atexit(close_all); }
    return g_all;
}

int ot_trio_open(ot_trio *t, int with_server) {
    memset(t, 0, sizeof *t);
    if (!U(InternetOpenA)) return 0;
    t->s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!t->s) return 0;
    unsigned short port = 80;
    if (with_server) { t->srv = srv_http(NULL, 0); if (!t->srv) return 0; port = srv_port(t->srv); }
    t->c = U(InternetConnectA)(t->s, "127.0.0.1", port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (t->c) t->r = U(HttpOpenRequestA)(t->c, "GET", "/trio", NULL, NULL, NULL, T_INET_FRESH, 0);
    return t->s && t->c && t->r;
}
void ot_trio_close(ot_trio *t) {
    if (t->r) U(InternetCloseHandle)(t->r);
    if (t->c) U(InternetCloseHandle)(t->c);
    if (t->s) U(InternetCloseHandle)(t->s);
    srv_stop(t->srv);
    memset(t, 0, sizeof *t);
}

/* Run "exe --child name args" with this process's stdout/stderr inherited (child lines land inside the
 * parent's RUN block). Returns the exit code, 0xDEAD0000 spawn failure, 0xDEAD0001 timeout (killed). */
DWORD ot_run_child_io(const char *name, const char *args, DWORD timeout_ms) {
    HANDLE o = GetStdHandle(STD_OUTPUT_HANDLE), e = GetStdHandle(STD_ERROR_HANDLE);
    if (o && o != INVALID_HANDLE_VALUE) SetHandleInformation(o, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    if (e && e != INVALID_HANDLE_VALUE) SetHandleInformation(e, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    fflush(stdout);
    PROCESS_INFORMATION pi; DWORD code = 0xDEAD0000;
    HANDLE h = t_spawn_child(name, args, 0, NULL, o, e, TRUE, NULL, &pi);
    if (!h) return code;
    if (WaitForSingleObject(h, timeout_ms) != WAIT_OBJECT_0) { TerminateProcess(h, 1); WaitForSingleObject(h, 5000); code = 0xDEAD0001; }
    else GetExitCodeProcess(h, &code);
    CloseHandle(pi.hThread); CloseHandle(h);
    return code;
}
