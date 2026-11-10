/* hci_util.c - helpers for the http_cache_integration area (see hci.h). */
#include "hci.h"
#include <stdlib.h>
#include <ctype.h>

/* ---------------------------------------------------------------- plan server */
static const char *reason(int st) {
    switch (st) {
    case 200: return "OK"; case 203: return "Non-Authoritative Information"; case 204: return "No Content";
    case 206: return "Partial Content"; case 301: return "Moved Permanently"; case 302: return "Found";
    case 303: return "See Other"; case 304: return "Not Modified"; case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect"; case 404: return "Not Found"; case 410: return "Gone";
    case 500: return "Internal Server Error"; default: return "X";
    }
}
static int send_reply(srv_conn *c, const hci_reply *r, int is_head, unsigned short port) {
    int st = r->status ? r->status : 200;
    size_t n = r->body ? (r->len ? r->len : strlen((const char *)r->body)) : 0;
    char head[2048]; int k = 0;
    k += snprintf(head + k, sizeof head - k, "HTTP/1.1 %d %s\r\n", st, reason(st));
    /* %P in hdrs -> port */
    for (const char *h = r->hdrs; *h && k < (int)sizeof head - 64; h++) {
        if (h[0] == '%' && h[1] == 'P') { k += snprintf(head + k, sizeof head - k, "%u", port); h++; }
        else head[k++] = *h;
    }
    if (!r->no_length && st != 304 && st != 204) k += snprintf(head + k, sizeof head - k, "Content-Length: %u\r\n", (unsigned)n);
    if (r->close || r->no_length) k += snprintf(head + k, sizeof head - k, "Connection: close\r\n");
    k += snprintf(head + k, sizeof head - k, "\r\n");
    if (srv_conn_send(c, head, k)) return -1;
    if (!is_head && n && st != 304 && st != 204 && srv_conn_send(c, r->body, n)) return -1;
    return (r->close || r->no_length) ? -1 : 0;
}
static int plan_fn(srv_conn *c, const srv_step *stp, void *user) {
    hci_plan *p = user; srv *s = srv_conn_server(c);
    for (int guard = 0; guard < 64; guard++) {
        if (!hci_wait_request(c)) return -1;
        int ri = srv_conn_recv_head(c);
        if (ri < 0) return -1;
        const char *m = srv_req_method(s, ri);
        int is_head = m && !strcmp(m, "HEAD");
        int cond = srv_req_header(s, ri, "If-None-Match") || srv_req_header(s, ri, "If-Modified-Since");
        const hci_reply *r;
        if (cond && p->has_cond) { r = &p->cond; InterlockedIncrement(&p->cond_served); }
        else { LONG k = InterlockedIncrement(&p->served) - 1; r = &p->r[k < p->n ? k : (p->n ? p->n - 1 : 0)]; }
        if (send_reply(c, r, is_head, srv_port(s)) < 0) return -1;
        const char *cn = srv_req_header(s, ri, "Connection");
        if (cn && strstr(cn, "close")) return -1;
    }
    return -1;
}
srv *hci_plan_start(hci_plan *p) {
    static const srv_step st[] = { S_CALL(plan_fn) };
    static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTP; cfg.scripts = sc; cfg.nscripts = 1; cfg.user = p; cfg.lifetime_ms = 30000;
    if (p->n == 0) { p->n = 1; p->r[0].status = 200; p->r[0].body = "hello"; }
    srv *s = NULL;
    if (srv_start(&cfg, &s) != SRV_OK) return NULL;
    return s;
}
static void vfmt(char *dst, size_t cap, const char *fmt, va_list a) { if (fmt) vsnprintf(dst, cap, fmt, a); else dst[0] = 0; }
hci_reply *hci_set(hci_plan *p, int i, int status, const char *body, const char *hdrfmt, ...) {
    hci_reply *r = &p->r[i]; memset(r, 0, sizeof *r);
    r->status = status; r->body = body;
    va_list a; va_start(a, hdrfmt); vfmt(r->hdrs, sizeof r->hdrs, hdrfmt, a); va_end(a);
    if (i + 1 > p->n) p->n = i + 1;
    return r;
}
hci_reply *hci_set_cond(hci_plan *p, int status, const char *hdrfmt, ...) {
    hci_reply *r = &p->cond; memset(r, 0, sizeof *r);
    r->status = status;
    va_list a; va_start(a, hdrfmt); vfmt(r->hdrs, sizeof r->hdrs, hdrfmt, a); va_end(a);
    p->has_cond = 1;
    return r;
}

/* ---------------------------------------------------------------- names and times */
static char g_urls[16][512]; static volatile LONG g_ui;
const char *hci_url_ext(srv *s, const char *tag, const char *ext) {
    char *b = g_urls[InterlockedIncrement(&g_ui) & 15];
    char path[300]; snprintf(path, sizeof path, "/%s%s%s", t_uniq(tag), ext ? "." : "", ext ? ext : "");
    snprintf(b, 512, "%s", srv_url(s, path));
    t_cache_track(b);
    return b;
}
const char *hci_url(srv *s, const char *tag) { return hci_url_ext(s, tag, NULL); }

LONGLONG hci_ft(FILETIME f) { return (LONGLONG)(((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime); }
LONGLONG hci_ft_now(void) { FILETIME f; GetSystemTimeAsFileTime(&f); return hci_ft(f); }
void hci_http_date(char *out, size_t cap, LONGLONG off) {
    static const char *wd[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    static const char *mo[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    LONGLONG t = hci_ft_now() + off * HCI_SEC; FILETIME f; f.dwLowDateTime = (DWORD)t; f.dwHighDateTime = (DWORD)(t >> 32);
    SYSTEMTIME st; FileTimeToSystemTime(&f, &st);
    snprintf(out, cap, "%s, %02u %s %04u %02u:%02u:%02u GMT", wd[st.wDayOfWeek], st.wDay, mo[st.wMonth - 1], st.wYear, st.wHour, st.wMinute, st.wSecond);
}

/* ---------------------------------------------------------------- client */
HINTERNET hci_open(void) { return t_inet_open("hci-agent"); }

static void fill_after_send(HINTERNET h, hci_resp *r) {
    DWORD st = 0, l = sizeof st;
    if (U(HttpQueryInfoA)(h, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL)) r->status = (int)st;
    l = sizeof r->reqflags;
    r->reqflags_ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_REQUEST_FLAGS, &r->reqflags, &l);
    l = sizeof r->rawhdrs - 1;
    if (!U(HttpQueryInfoA)(h, HTTP_QUERY_RAW_HEADERS_CRLF, r->rawhdrs, &l, NULL)) r->rawhdrs[0] = 0;
    l = sizeof r->url_opt - 1;
    if (!U(InternetQueryOptionA)(h, INTERNET_OPTION_URL, r->url_opt, &l)) r->url_opt[0] = 0;
    l = sizeof r->datafile_early - 1; SetLastError(0);
    if (!U(InternetQueryOptionA)(h, INTERNET_OPTION_DATAFILE_NAME, r->datafile_early, &l)) { r->datafile_early[0] = 0; r->datafile_early_err = GetLastError(); }
}
static void fill_after_read(HINTERNET h, hci_resp *r) {
    DWORD l = sizeof r->datafile - 1; SetLastError(0);
    if (!U(InternetQueryOptionA)(h, INTERNET_OPTION_DATAFILE_NAME, r->datafile, &l)) { r->datafile[0] = 0; r->datafile_err = GetLastError(); }
}
int hci_get(HINTERNET hi, const char *url, const char *hdrs, DWORD flags, hci_resp *r) {
    memset(r, 0, sizeof *r);
    HINTERNET h = U(InternetOpenUrlA)(hi, url, hdrs, hdrs ? (DWORD)-1 : 0, flags, 0);
    if (!h) { r->err = GetLastError(); return 0; }
    r->ok = 1;
    fill_after_send(h, r);
    int ok; r->len = t_inet_read_all(h, r->body, sizeof r->body, &ok); r->read_ok = ok;
    fill_after_read(h, r);
    U(InternetCloseHandle)(h);
    return r->status;
}
int hci_req(HINTERNET hi, srv *s, const char *verb, const char *url, DWORD flags, const char *hdrs,
            const void *body, DWORD blen, hci_setup_fn setup, void *ctx, hci_resp *r) {
    memset(r, 0, sizeof *r);
    URL_COMPONENTSA uc; memset(&uc, 0, sizeof uc); uc.dwStructSize = sizeof uc;
    char host[256], path[1024]; uc.lpszHostName = host; uc.dwHostNameLength = sizeof host; uc.lpszUrlPath = path; uc.dwUrlPathLength = sizeof path;
    char extra[512]; uc.lpszExtraInfo = extra; uc.dwExtraInfoLength = sizeof extra;
    if (!U(InternetCrackUrlA)(url, 0, 0, &uc)) { r->err = GetLastError(); return 0; }
    char obj[1600]; snprintf(obj, sizeof obj, "%s%s", path, extra);
    HINTERNET hc = U(InternetConnectA)(hi, host, uc.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hc) { r->err = GetLastError(); return 0; }
    if (uc.nScheme == INTERNET_SCHEME_HTTPS) flags |= INTERNET_FLAG_SECURE;
    HINTERNET h = U(HttpOpenRequestA)(hc, verb, obj, NULL, NULL, NULL, flags, 0);
    if (!h) { r->err = GetLastError(); U(InternetCloseHandle)(hc); return 0; }
    if (uc.nScheme == INTERNET_SCHEME_HTTPS) t_https_secflags(h, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    if (setup) setup(h, ctx);
    if (!U(HttpSendRequestA)(h, hdrs, hdrs ? (DWORD)-1 : 0, (LPVOID)body, blen)) {
        r->err = GetLastError(); U(InternetCloseHandle)(h); U(InternetCloseHandle)(hc); return 0;
    }
    r->ok = 1;
    fill_after_send(h, r);
    int ok; r->len = t_inet_read_all(h, r->body, sizeof r->body, &ok); r->read_ok = ok;
    fill_after_read(h, r);
    U(InternetCloseHandle)(h); U(InternetCloseHandle)(hc);
    return r->status;
}

/* ---------------------------------------------------------------- cache */
INTERNET_CACHE_ENTRY_INFOA *hci_info(const char *url, DWORD *err) {
    DWORD n = 0; if (err) *err = 0;
    SetLastError(0);
    if (U(GetUrlCacheEntryInfoA)(url, NULL, &n)) { if (err) *err = 0xFFFFFFFF; return NULL; }
    DWORD e = GetLastError();
    if (e != ERROR_INSUFFICIENT_BUFFER) { if (err) *err = e; return NULL; }
    INTERNET_CACHE_ENTRY_INFOA *p = calloc(1, n + 16);
    if (!U(GetUrlCacheEntryInfoA)(url, p, &n)) { if (err) *err = GetLastError(); free(p); return NULL; }
    return p;
}
int hci_exists(const char *url) { DWORD e; INTERNET_CACHE_ENTRY_INFOA *p = hci_info(url, &e); free(p); return p != NULL; }
int hci_file_read(const char *path, char *buf, size_t cap, size_t *n) {
    *n = 0;
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD rd = 0; BOOL ok = ReadFile(f, buf, (DWORD)(cap - 1), &rd, NULL);
    CloseHandle(f);
    buf[rd] = 0; *n = rd;
    return ok;
}
int hci_file_exists(const char *path) { return path && path[0] && GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES; }
static const char *stristr(const char *h, const char *n) {
    size_t ln = strlen(n);
    for (; h && *h; h++) if (!_strnicmp(h, n, ln)) return h;
    return NULL;
}
int hci_hdr_has(const INTERNET_CACHE_ENTRY_INFOA *e, const char *needle) {
    if (!e || !e->lpHeaderInfo || !e->dwHeaderInfoSize) return 0;
    return stristr((const char *)e->lpHeaderInfo, needle) != NULL;
}
const char *hci_ext_of(const INTERNET_CACHE_ENTRY_INFOA *e) { return e && e->lpszFileExtension ? e->lpszFileExtension : ""; }
const char *hci_local_ext(const INTERNET_CACHE_ENTRY_INFOA *e) {
    if (!e || !e->lpszLocalFileName) return "";
    const char *slash = strrchr(e->lpszLocalFileName, '\\'), *dot = strrchr(e->lpszLocalFileName, '.');
    if (!dot || (slash && dot < slash)) return "";
    return dot + 1;
}
void hci_note_entry(const char *what, const INTERNET_CACHE_ENTRY_INFOA *e) {
    if (!e) { t_note("%s: no entry", what); return; }
    char hb[512]; size_t k = 0;
    if (e->lpHeaderInfo) for (DWORD i = 0; i < e->dwHeaderInfoSize && k < sizeof hb - 3; i++) {
        char ch = ((const char *)e->lpHeaderInfo)[i];
        if (ch == '\r') { hb[k++] = '\\'; hb[k++] = 'r'; } else if (ch == '\n') { hb[k++] = '\\'; hb[k++] = 'n'; } else if (ch) hb[k++] = ch; else hb[k++] = '0';
    }
    hb[k] = 0;
    t_note("%s: type=0x%lx size=%lu use=%lu hit=%lu ext=%s local=%s hdrsize=%lu exp=%llx lm=%llx sync=%llx acc=%llx hdrs=[%s]",
           what, e->CacheEntryType, e->dwSizeLow, e->dwUseCount, e->dwHitRate, hci_ext_of(e),
           e->lpszLocalFileName ? e->lpszLocalFileName : "(null)", e->dwHeaderInfoSize,
           (unsigned long long)hci_ft(e->ExpireTime), (unsigned long long)hci_ft(e->LastModifiedTime),
           (unsigned long long)hci_ft(e->LastSyncTime), (unsigned long long)hci_ft(e->LastAccessTime), hb);
}
BOOL hci_delete(const char *url) { return U(DeleteUrlCacheEntryA)(url); }
int hci_reqs(srv *s, int n) { if (n > 0) srv_wait_requests(s, n, 1500); return srv_req_count(s); }

/* ---------------------------------------------------------------- pass-2 helpers */
INTERNET_CACHE_ENTRY_INFOA *hci_fetch(const char *url, const char *hdrs, DWORD flags, hci_resp *r) {
    HINTERNET hi = hci_open();
    hci_get(hi, url, hdrs, flags, r);
    t_inet_close(hi);
    DWORD e; return hci_info(url, &e);
}
int hci_near(LONGLONG v, LONGLONG want, LONGLONG tol) { LONGLONG d = v - want; if (d < 0) d = -d; return d <= tol * HCI_SEC; }
FILETIME hci_ft_make(LONGLONG t) { FILETIME f; f.dwLowDateTime = (DWORD)t; f.dwHighDateTime = (DWORD)((ULONGLONG)t >> 32); return f; }
FILETIME hci_ft_off(LONGLONG off) { return hci_ft_make(hci_ft_now() + off * HCI_SEC); }
BOOL hci_set_times(const char *url, LONGLONG exp_off, LONGLONG lm_off, LONGLONG sync_off) {
    INTERNET_CACHE_ENTRY_INFOA ci; memset(&ci, 0, sizeof ci); ci.dwStructSize = sizeof ci;
    DWORD fc = 0;
    if (exp_off != HCI_KEEP) { ci.ExpireTime = hci_ft_off(exp_off); fc |= CACHE_ENTRY_EXPTIME_FC; }
    if (lm_off != HCI_KEEP) { ci.LastModifiedTime = hci_ft_off(lm_off); fc |= CACHE_ENTRY_MODTIME_FC; }
    if (sync_off != HCI_KEEP) { ci.LastSyncTime = hci_ft_off(sync_off); fc |= CACHE_ENTRY_SYNCTIME_FC; }
    return U(SetUrlCacheEntryInfoA)(url, &ci, fc);
}
BOOL hci_set_type(const char *url, DWORD type) {
    INTERNET_CACHE_ENTRY_INFOA ci; memset(&ci, 0, sizeof ci); ci.dwStructSize = sizeof ci; ci.CacheEntryType = type;
    return U(SetUrlCacheEntryInfoA)(url, &ci, CACHE_ENTRY_ATTRIBUTE_FC);
}
int hci_file_eq(const char *path, const void *p, size_t n) {
    if (!path || !path[0]) return 0;
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    char *b = malloc(n + 2); DWORD rd = 0, tot = 0; int ok = 1;
    while (tot < n + 1 && ReadFile(f, b + tot, (DWORD)(n + 1 - tot), &rd, NULL) && rd) tot += rd;
    CloseHandle(f);
    ok = tot == n && !memcmp(b, p, n);
    free(b);
    return ok;
}
LONGLONG hci_ft_utc(int y, int mo, int d, int h, int mi, int s) {
    SYSTEMTIME st; memset(&st, 0, sizeof st);
    st.wYear = (WORD)y; st.wMonth = (WORD)mo; st.wDay = (WORD)d; st.wHour = (WORD)h; st.wMinute = (WORD)mi; st.wSecond = (WORD)s;
    FILETIME f; if (!SystemTimeToFileTime(&st, &f)) return -1;
    return hci_ft(f);
}
const char *hci_rh(srv *s, int i, const char *name) { return i < srv_req_count(s) ? srv_req_header(s, i, name) : NULL; }
int hci_seed(const char *url, const char *body, const char *hdrs, DWORD type, LONGLONG exp_sec, LONGLONG lm_sec) {
    char path[MAX_PATH + 1];
    if (!U(CreateUrlCacheEntryA)(url, 0, "txt", path, 0)) return 0;
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD w; WriteFile(f, body, (DWORD)strlen(body), &w, NULL); CloseHandle(f);
    FILETIME ex = {0}, lm = {0};
    if (exp_sec) ex = hci_ft_off(exp_sec);
    if (lm_sec) lm = hci_ft_off(lm_sec);
    t_cache_track(url);
    return U(CommitUrlCacheEntryA)(url, path, ex, lm, type, (BYTE *)hdrs, hdrs ? (DWORD)strlen(hdrs) : 0, "txt", NULL);
}
