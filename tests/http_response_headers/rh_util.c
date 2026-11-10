/* rh_util.c - helpers for the http_response_headers area. See rh.h. */
#include "rh.h"

DWORD rh_err, rh_len;
BOOL  rh_ok;

#define RH_NBUF 8
#define RH_BUFSZ (512 * 1024)
static char  g_buf[RH_NBUF][RH_BUFSZ];
static WCHAR g_wbuf[RH_BUFSZ / 2];
static int   g_rot;
static char *nextbuf(void) { g_rot = (g_rot + 1) % RH_NBUF; return g_buf[g_rot]; }

int rh_acp1252(void) { return GetACP() == 1252; }

const char *rh_esc(const char *p, size_t n) {
    static char out[4][1200]; static int r; r = (r + 1) % 4;
    char *o = out[r]; size_t k = 0;
    if (!p) return "(null)";
    for (size_t i = 0; i < n && k < sizeof out[0] - 8; i++) {
        unsigned char ch = (unsigned char)p[i];
        if (ch == '\r') { o[k++] = '\\'; o[k++] = 'r'; }
        else if (ch == '\n') { o[k++] = '\\'; o[k++] = 'n'; }
        else if (ch == 0) { o[k++] = '\\'; o[k++] = '0'; }
        else if (ch < 32 || ch >= 127) k += (size_t)snprintf(o + k, 8, "\\x%02x", ch);
        else o[k++] = (char)ch;
    }
    if (k >= sizeof out[0] - 8) { o[k++] = '.'; o[k++] = '.'; }
    o[k] = 0;
    return o;
}

int rh_start(rh_t *c, const srv_step *steps, int n) {
    memset(c, 0, sizeof *c);
    if (n > (int)(sizeof c->st / sizeof c->st[0])) n = (int)(sizeof c->st / sizeof c->st[0]);
    memcpy(c->st, steps, sizeof(srv_step) * (size_t)n);
    c->sc.steps = c->st; c->sc.nsteps = n;
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTP; cfg.scripts = &c->sc; cfg.nscripts = 1; cfg.lifetime_ms = 30000; cfg.v4_only = 1;
    int rc = srv_start(&cfg, &c->s);
    if (rc) { c->s = NULL; t_skip("server unavailable: %s", srv_strerror(rc)); return 0; }
    return 1;
}

int rh_open_v(rh_t *c, const char *verb, const char *path, const char *version, DWORD flags) {
    if (!U(InternetConnectA) || !U(HttpOpenRequestA)) { t_skip("missing wininet exports"); return 0; }
    c->hi = t_inet_open("rh-agent/1.0");
    c->hc = c->hi ? U(InternetConnectA)(c->hi, "127.0.0.1", srv_port(c->s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    c->hr = c->hc ? U(HttpOpenRequestA)(c->hc, verb ? verb : "GET", path ? path : "/r", version, NULL, NULL, flags ? flags : RH_FLAGS, 0) : NULL;
    CHECKF(c->hi && c->hc && c->hr, "open chain err=%lu", GetLastError());
    return c->hr != NULL;
}
int rh_open(rh_t *c, const char *verb, const char *path, DWORD flags) { return rh_open_v(c, verb, path, NULL, flags); }

BOOL rh_send(rh_t *c, const char *hdrs, const void *opt, DWORD optlen) {
    SetLastError(0);
    c->sent = U(HttpSendRequestA)(c->hr, hdrs, hdrs ? (DWORD)-1 : 0, (void *)opt, optlen);
    c->err = c->sent ? 0 : GetLastError();
    return c->sent;
}

int rh_raw_nosend(rh_t *c, const char *verb, const void *raw, size_t n) {
    srv_step st[] = { S_HEAD(), S_BODY(), S_SENDN(raw, n), S_CLOSE() };
    if (!rh_start(c, st, 4)) return 0;
    if (!rh_open(c, verb, "/r", 0)) { rh_close(c); t_skip("open failed"); return 0; }
    return 1;
}

int rh_raw(rh_t *c, const char *verb, const void *raw, size_t n) {
    if (!rh_raw_nosend(c, verb, raw, n)) return 0;
    rh_send(c, NULL, NULL, 0);
    return 1;
}

void rh_close(rh_t *c) {
    if (c->hr) U(InternetCloseHandle)(c->hr);
    if (c->hc) U(InternetCloseHandle)(c->hc);
    if (c->hi) U(InternetCloseHandle)(c->hi);
    c->hr = c->hc = c->hi = NULL;
    if (c->s) srv_stop(c->s);
    c->s = NULL;
}

size_t rh_body(rh_t *c, char *buf, size_t cap) { int ok; return t_inet_read_all(c->hr, buf, cap, &ok); }

/* ------------------------------------------------------------------ raw calls */
BOOL rh_callA(HINTERNET h, DWORD level, void *buf, DWORD len, DWORD *idx) {
    rh_len = len; SetLastError(0xBEEF);
    rh_ok = U(HttpQueryInfoA)(h, level, buf, &rh_len, idx);
    rh_err = rh_ok ? 0 : GetLastError();
    return rh_ok;
}
BOOL rh_callW(HINTERNET h, DWORD level, void *buf, DWORD len, DWORD *idx) {
    rh_len = len; SetLastError(0xBEEF);
    rh_ok = U(HttpQueryInfoW)(h, level, buf, &rh_len, idx);
    rh_err = rh_ok ? 0 : GetLastError();
    return rh_ok;
}

const char *rh_qa(HINTERNET h, DWORD level, DWORD *idx) {
    char *b = nextbuf(); b[0] = 0;
    if (!rh_callA(h, level, b, RH_BUFSZ - 1, idx)) return NULL;
    return b;
}
const char *rh_qac(HINTERNET h, const char *name, DWORD mods, DWORD *idx) {
    char *b = nextbuf();
    lstrcpynA(b, name, RH_BUFSZ - 1);
    if (!rh_callA(h, HTTP_QUERY_CUSTOM | mods, b, RH_BUFSZ - 1, idx)) return NULL;
    return b;
}
static const char *w2a(DWORD bytes) {
    char *b = nextbuf();
    int nch = (int)(bytes / 2);
    int k = WideCharToMultiByte(CP_ACP, 0, g_wbuf, nch, b, RH_BUFSZ - 1, NULL, NULL);
    b[k > 0 ? k : 0] = 0;
    return b;
}
const char *rh_qw(HINTERNET h, DWORD level, DWORD *idx) {
    g_wbuf[0] = 0;
    if (!rh_callW(h, level, g_wbuf, sizeof g_wbuf - 2, idx)) return NULL;
    return w2a(rh_len);
}
const char *rh_qwc(HINTERNET h, const char *name, DWORD mods, DWORD *idx) {
    MultiByteToWideChar(CP_ACP, 0, name, -1, g_wbuf, RH_BUFSZ / 2 - 1);
    if (!rh_callW(h, HTTP_QUERY_CUSTOM | mods, g_wbuf, sizeof g_wbuf - 2, idx)) return NULL;
    return w2a(rh_len);
}
const WCHAR *rh_lastw(void) { return g_wbuf; }

BOOL rh_qnum(HINTERNET h, DWORD level, DWORD *out) { *out = 0xA5A5A5A5; return rh_callA(h, level | HTTP_QUERY_FLAG_NUMBER, out, sizeof *out, NULL); }
BOOL rh_qnum64(HINTERNET h, DWORD level, ULONGLONG *out) { *out = 0xA5A5A5A5A5A5A5A5ull; return rh_callA(h, level | HTTP_QUERY_FLAG_NUMBER64, out, sizeof *out, NULL); }
BOOL rh_qtime(HINTERNET h, DWORD level, SYSTEMTIME *out) { memset(out, 0xA5, sizeof *out); return rh_callA(h, level | HTTP_QUERY_FLAG_SYSTEMTIME, out, sizeof *out, NULL); }
static BOOL qcustom_bin(HINTERNET h, const char *name, DWORD mod, void *out, DWORD sz) {
    char b[256]; lstrcpynA(b, name, sizeof b);
    BOOL ok = rh_callA(h, HTTP_QUERY_CUSTOM | mod, b, sizeof b, NULL);
    if (ok) memcpy(out, b, sz);
    return ok;
}
BOOL rh_qnumc(HINTERNET h, const char *name, DWORD *out) { *out = 0xA5A5A5A5; return qcustom_bin(h, name, HTTP_QUERY_FLAG_NUMBER, out, sizeof *out); }
BOOL rh_qnum64c(HINTERNET h, const char *name, ULONGLONG *out) { *out = 0xA5A5A5A5A5A5A5A5ull; return qcustom_bin(h, name, HTTP_QUERY_FLAG_NUMBER64, out, sizeof *out); }
BOOL rh_qtimec(HINTERNET h, const char *name, SYSTEMTIME *out) { memset(out, 0xA5, sizeof *out); return qcustom_bin(h, name, HTTP_QUERY_FLAG_SYSTEMTIME, out, sizeof *out); }

/* ------------------------------------------------------------------ expectations */
static void expect_res(const char *got, const char *want, const char *api, DWORD level, const char *file, int line) {
    char expr[96]; snprintf(expr, sizeof expr, "%s(level=%lu/0x%lx)", api, level & 0xFFFF, level);
    if (!want) {
        t_check(!got && rh_err == ERROR_HTTP_HEADER_NOT_FOUND, file, line, expr, "want 12150, got %s err=%lu",
                got ? rh_esc(got, strlen(got)) : "(fail)", rh_err);
        return;
    }
    t_check(got && !strcmp(got, want), file, line, expr, "got \"%s\" err=%lu want \"%s\"",
            got ? rh_esc(got, strlen(got)) : "(fail)", rh_err, rh_esc(want, strlen(want)));
}
void rh_expect_a(HINTERNET h, DWORD level, const char *want, const char *file, int line) {
    const char *g = rh_qa(h, level, NULL);
    expect_res(g, want, "HttpQueryInfoA", level, file, line);
    if (g && want) t_check(rh_len == strlen(want), file, line, "A length", "len=%lu want %u", rh_len, (unsigned)strlen(want));
}
void rh_expect_w(HINTERNET h, DWORD level, const char *want, const char *file, int line) {
    const char *g = rh_qw(h, level, NULL);
    expect_res(g, want, "HttpQueryInfoW", level, file, line);
    if (g && want) t_check(rh_len == 2 * strlen(want), file, line, "W length (bytes)", "len=%lu want %u", rh_len, (unsigned)(2 * strlen(want)));
}
void rh_expect_c(HINTERNET h, const char *name, const char *want, const char *file, int line) {
    char expr[160];
    const char *g = rh_qac(h, name, 0, NULL);
    snprintf(expr, sizeof expr, "HttpQueryInfoA(CUSTOM \"%s\")", name);
    if (!want) t_check(!g && rh_err == ERROR_HTTP_HEADER_NOT_FOUND, file, line, expr, "want 12150, got %s err=%lu", g ? rh_esc(g, strlen(g)) : "(fail)", rh_err);
    else t_check(g && !strcmp(g, want) && rh_len == strlen(want), file, line, expr, "got \"%s\" len=%lu err=%lu want \"%s\"",
                 g ? rh_esc(g, strlen(g)) : "(fail)", rh_len, rh_err, rh_esc(want, strlen(want)));
    g = rh_qwc(h, name, 0, NULL);
    snprintf(expr, sizeof expr, "HttpQueryInfoW(CUSTOM \"%s\")", name);
    if (!want) t_check(!g && rh_err == ERROR_HTTP_HEADER_NOT_FOUND, file, line, expr, "want 12150, got %s err=%lu", g ? rh_esc(g, strlen(g)) : "(fail)", rh_err);
    else t_check(g && !strcmp(g, want) && rh_len == 2 * strlen(want), file, line, expr, "got \"%s\" len=%lu err=%lu want \"%s\"",
                 g ? rh_esc(g, strlen(g)) : "(fail)", rh_len, rh_err, rh_esc(want, strlen(want)));
}
void rh_expect_err(HINTERNET h, DWORD level, DWORD err, int wide, const char *file, int line) {
    char expr[96]; snprintf(expr, sizeof expr, "HttpQueryInfo%c(level=%lu flags=0x%lx) fails", wide ? 'W' : 'A', level & 0x3FFFFFF, level & 0xFC000000);
    const char *g = wide ? rh_qw(h, level, NULL) : rh_qa(h, level, NULL);
    t_check(!g && rh_err == err, file, line, expr, "want err %lu, got %s err=%lu", err, g ? "success" : "fail", rh_err);
}
void rh_expect_cerr(HINTERNET h, const char *name, DWORD mods, DWORD err, const char *file, int line) {
    char expr[160]; snprintf(expr, sizeof expr, "HttpQueryInfoA(CUSTOM \"%s\" mods=0x%lx) fails", name, mods);
    const char *g = rh_qac(h, name, mods, NULL);
    t_check(!g && rh_err == err, file, line, expr, "want err %lu, got %s err=%lu", err, g ? "success" : "fail", rh_err);
}
/* GlobalKnownHeaders of Win10 wininet.dll 11.0.19041 (rva 0x1f3660, 24-byte entries: name, length, modifier mask) [D] */
const rh_known_t rh_known[96] = {
    { "Mime-Version", 0x80000000u }, /* 0 */
    { "Content-Type", 0x80000000u }, /* 1 */
    { "Content-Transfer-Encoding", 0x80000000u }, /* 2 */
    { "Content-Id", 0x80000000u }, /* 3 */
    { "Content-Description", 0x80000000u }, /* 4 */
    { "Content-Length", 0xa8000000u }, /* 5 */
    { "Content-Language", 0x80000000u }, /* 6 */
    { "Allow", 0x80000000u }, /* 7 */
    { "Public", 0x80000000u }, /* 8 */
    { "Date", 0xc0000000u }, /* 9 */
    { "Expires", 0x80000000u }, /* 10 */
    { "Last-Modified", 0xc0000000u }, /* 11 */
    { "Message-id", 0x80000000u }, /* 12 */
    { "Uri", 0x80000000u }, /* 13 */
    { "Derived-From", 0x80000000u }, /* 14 */
    { "Cost", 0x80000000u }, /* 15 */
    { "Link", 0x80000000u }, /* 16 */
    { "Pragma", 0x80000000u }, /* 17 */
    { NULL, 0x80000000u }, /* 18 */
    { NULL, 0x20000000u }, /* 19 */
    { NULL, 0x00000000u }, /* 20 */
    { NULL, 0x80000000u }, /* 21 */
    { NULL, 0x80000000u }, /* 22 */
    { "Connection", 0x80000000u }, /* 23 */
    { "Accept", 0x80000000u }, /* 24 */
    { "Accept-Charset", 0x80000000u }, /* 25 */
    { "Accept-Encoding", 0x80000000u }, /* 26 */
    { "Accept-Language", 0x80000000u }, /* 27 */
    { "Authorization", 0x80000000u }, /* 28 */
    { "Content-Encoding", 0x80000000u }, /* 29 */
    { "Forwarded", 0x80000000u }, /* 30 */
    { "From", 0x80000000u }, /* 31 */
    { "If-Modified-Since", 0xc0000000u }, /* 32 */
    { "Location", 0x80000000u }, /* 33 */
    { "Orig-Uri", 0x80000000u }, /* 34 */
    { "Referer", 0x80000000u }, /* 35 */
    { "Retry-After", 0xc0000000u }, /* 36 */
    { "Server", 0x80000000u }, /* 37 */
    { "Title", 0x80000000u }, /* 38 */
    { "User-Agent", 0x80000000u }, /* 39 */
    { "WWW-Authenticate", 0x80000000u }, /* 40 */
    { "Proxy-Authenticate", 0x80000000u }, /* 41 */
    { "Accept-Ranges", 0x80000000u }, /* 42 */
    { "Set-Cookie", 0x80000000u }, /* 43 */
    { "Cookie", 0x80000000u }, /* 44 */
    { NULL, 0x80000000u }, /* 45 */
    { "Refresh", 0x00000000u }, /* 46 */
    { "Content-Disposition", 0x80000000u }, /* 47 */
    { "Age", 0x80000000u }, /* 48 */
    { "Cache-Control", 0x80000000u }, /* 49 */
    { "Content-Base", 0x80000000u }, /* 50 */
    { "Content-Location", 0x80000000u }, /* 51 */
    { "Content-Md5", 0x80000000u }, /* 52 */
    { "Content-Range", 0x80000000u }, /* 53 */
    { "Etag", 0x80000000u }, /* 54 */
    { "Host", 0x80000000u }, /* 55 */
    { "If-Match", 0x80000000u }, /* 56 */
    { "If-None-Match", 0x80000000u }, /* 57 */
    { "If-Range", 0x80000000u }, /* 58 */
    { "If-Unmodified-Since", 0xc0000000u }, /* 59 */
    { "Max-Forwards", 0x80000000u }, /* 60 */
    { "Proxy-Authorization", 0x80000000u }, /* 61 */
    { "Range", 0x80000000u }, /* 62 */
    { "Transfer-Encoding", 0x80000000u }, /* 63 */
    { "Upgrade", 0x80000000u }, /* 64 */
    { "Vary", 0x80000000u }, /* 65 */
    { "Via", 0x80000000u }, /* 66 */
    { "Warning", 0x80000000u }, /* 67 */
    { "Expect", 0xc0000000u }, /* 68 */
    { "Proxy-Connection", 0x80000000u }, /* 69 */
    { "Unless-Modified-Since", 0x80000000u }, /* 70 */
    { "Ms-Echo-Request", 0x00000000u }, /* 71 */
    { "Ms-Echo-Reply", 0x80000000u }, /* 72 */
    { NULL, 0x80000000u }, /* 73 */
    { NULL, 0x80000000u }, /* 74 */
    { "Proxy-Support", 0x80000000u }, /* 75 */
    { "Authentication-Info", 0x80000000u }, /* 76 */
    { "PassportURLs", 0x80000000u }, /* 77 */
    { "PassportConfig", 0x80000000u }, /* 78 */
    { "X-Content-Type-Options", 0x80000000u }, /* 79 */
    { "P3P", 0x80000000u }, /* 80 */
    { "X-P2P-PeerDist", 0x80000000u }, /* 81 */
    { "Translate", 0x80000000u }, /* 82 */
    { "X-UA-Compatible", 0x80000000u }, /* 83 */
    { "Default-Style", 0x80000000u }, /* 84 */
    { "X-Frame-Options", 0x80000000u }, /* 85 */
    { "X-XSS-Protection", 0x80000000u }, /* 86 */
    { "Set-Cookie2", 0x80000000u }, /* 87 */
    { "DNT", 0x80000000u }, /* 88 */
    { "Keep-Alive", 0x80000000u }, /* 89 */
    { "HTTP2-Settings", 0x80000000u }, /* 90 */
    { "Strict-Transport-Security", 0x80000000u }, /* 91 */
    { "Sec-Token-Binding", 0x80000000u }, /* 92 */
    { "Include-Referred-Token-Binding-ID", 0x80000000u }, /* 93 */
    { "Public-Key-Pins", 0x80000000u }, /* 94 */
    { "Public-Key-Pins-Report-Only", 0x80000000u }, /* 95 */
};
