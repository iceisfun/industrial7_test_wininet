/* rs_common.c - router server, status-callback recorder and request helper for http_redirect_status. */
#include "rs.h"
#include <stdlib.h>

const char *rs_reason(int c) {
    switch (c) {
    case 100: return "Continue"; case 101: return "Switching Protocols"; case 102: return "Processing"; case 103: return "Early Hints";
    case 200: return "OK"; case 201: return "Created"; case 202: return "Accepted"; case 203: return "Non-Authoritative Information";
    case 204: return "No Content"; case 205: return "Reset Content"; case 206: return "Partial Content"; case 207: return "Multi-Status";
    case 208: return "Already Reported"; case 226: return "IM Used";
    case 300: return "Multiple Choices"; case 301: return "Moved Permanently"; case 302: return "Found"; case 303: return "See Other";
    case 304: return "Not Modified"; case 305: return "Use Proxy"; case 306: return "Switch Proxy"; case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request"; case 401: return "Unauthorized"; case 402: return "Payment Required"; case 403: return "Forbidden";
    case 404: return "Not Found"; case 405: return "Method Not Allowed"; case 406: return "Not Acceptable";
    case 407: return "Proxy Authentication Required"; case 408: return "Request Timeout"; case 409: return "Conflict";
    case 410: return "Gone"; case 411: return "Length Required"; case 412: return "Precondition Failed"; case 413: return "Payload Too Large";
    case 414: return "URI Too Long"; case 415: return "Unsupported Media Type"; case 416: return "Range Not Satisfiable";
    case 417: return "Expectation Failed"; case 418: return "I'm a teapot"; case 421: return "Misdirected Request";
    case 422: return "Unprocessable Entity"; case 423: return "Locked"; case 424: return "Failed Dependency"; case 425: return "Too Early";
    case 426: return "Upgrade Required"; case 428: return "Precondition Required"; case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large"; case 451: return "Unavailable For Legal Reasons";
    case 500: return "Internal Server Error"; case 501: return "Not Implemented"; case 502: return "Bad Gateway";
    case 503: return "Service Unavailable"; case 504: return "Gateway Timeout"; case 505: return "HTTP Version Not Supported";
    case 506: return "Variant Also Negotiates"; case 507: return "Insufficient Storage"; case 508: return "Loop Detected";
    case 510: return "Not Extended"; case 511: return "Network Authentication Required";
    default: return "Status";
    }
}

void rs_router_init(rs_router *r) {
    memset(r, 0, sizeof *r);
    snprintf(r->tok, sizeof r->tok, "rs%lu", GetCurrentProcessId());
}
rs_route *rs_addx(rs_router *r, const char *path, int code, const char *hdrs, const char *body, unsigned flags) {
    if (r->n >= RS_MAXR) return &r->r[RS_MAXR - 1];
    rs_route *e = &r->r[r->n++];
    memset(e, 0, sizeof *e);
    e->path = path; e->code = code; e->hdrs = hdrs; e->body = body; e->flags = flags;
    return e;
}
void rs_add(rs_router *r, const char *path, int code, const char *hdrs, const char *body) { rs_addx(r, path, code, hdrs, body, 0); }

static const rs_route *match(rs_router *r, const char *tgt) {
    for (int i = 0; i < r->n; i++) {
        const char *p = r->r[i].path; size_t n = strlen(p);
        if (n && p[n - 1] == '*') { if (!strncmp(tgt, p, n - 1)) return &r->r[i]; }
        else if (!strcmp(tgt, p)) return &r->r[i];
    }
    return NULL;
}

static size_t expand(rs_router *r, const char *tmpl, const char *tgt, char *out, size_t cap) {
    size_t o = 0;
    if (!tmpl) { out[0] = 0; return 0; }
    for (const char *p = tmpl; *p && o + 64 < cap; p++) {
        if (*p != '%' || !p[1]) { out[o++] = *p; continue; }
        p++;
        switch (*p) {
        case 'P': o += snprintf(out + o, cap - o, "%u", srv_port(r->s)); break;
        case 'A': o += snprintf(out + o, cap - o, "%u", r->alt_port); break;
        case 'U': o += snprintf(out + o, cap - o, "%s", r->tok); break;
        case 'N': {
            const char *l = strstr(tgt, "/loop/"); long n = l ? strtol(l + 6, NULL, 10) : 0;
            o += snprintf(out + o, cap - o, "%ld", n + 1); break;
        }
        case '%': out[o++] = '%'; break;
        default: out[o++] = '%'; out[o++] = *p; break;
        }
    }
    out[o] = 0;
    return o;
}

static int router_fn(srv_conn *c, const srv_step *st, void *user) {
    rs_router *r = (rs_router *)user; srv *s = srv_conn_server(c);
    (void)st;
    for (int it = 0; it < 400; it++) {
        int ri = srv_conn_recv_head(c);
        if (ri < 0) return -1;
        InterlockedIncrement(&r->hits);
        const char *tgt = srv_req_target(s, ri); const char *m = srv_req_method(s, ri);
        if (!tgt) tgt = "/";
        const rs_route *e = match(r, tgt);
        rs_route nf = { "", 404, NULL, "no route", 0 };
        if (!e) e = &nf;
        rs_route c304;
        if ((e->flags & RS_F_COND304) && (srv_req_header(s, ri, "If-None-Match") || srv_req_header(s, ri, "If-Modified-Since"))) {
            c304 = *e; c304.code = 304; c304.body = ""; c304.flags &= ~(RS_F_BIGBODY | RS_F_CHUNKED); e = &c304;
        }
        char *hb = malloc(16384); size_t h = 0;
        if (e->pre) h += expand(r, e->pre, tgt, hb + h, 4096);
        if (e->flags & RS_F_100) h += snprintf(hb + h, 16384 - h, "HTTP/1.1 100 Continue\r\n\r\n");
        if (e->flags & RS_F_RAWSTATUS) h += snprintf(hb + h, 16384 - h, "%s\r\n", e->reason ? e->reason : "HTTP/1.1 200 OK");
        else h += snprintf(hb + h, 16384 - h, "HTTP/1.%d %d %s\r\n", (e->flags & RS_F_HTTP10) ? 0 : 1, e->code, e->reason ? e->reason : rs_reason(e->code));
        h += expand(r, e->hdrs, tgt, hb + h, 8192);
        const char *body = e->body ? e->body : ""; size_t nb = strlen(body); char *big = NULL;
        if (e->flags & RS_F_BIGBODY) {
            nb = (size_t)e->code2; big = malloc(nb + 1);
            for (size_t i = 0; i < nb; i++) big[i] = (char)srv_pattern_byte(i);
            body = big;
        }
        int nobody_status = (e->code >= 100 && e->code < 200) || e->code == 204 || e->code == 304;
        if (e->flags & RS_F_CHUNKED) h += snprintf(hb + h, 16384 - h, "Transfer-Encoding: chunked\r\n");
        else if (e->flags & (RS_F_NOLEN | RS_F_NOBODYLEN)) {}
        else if (!(nobody_status && nb == 0)) h += snprintf(hb + h, 16384 - h, "Content-Length: %u\r\n", (unsigned)nb);
        if (e->flags & RS_F_CLOSE) h += snprintf(hb + h, 16384 - h, "Connection: close\r\n");
        h += snprintf(hb + h, 16384 - h, "\r\n");
        int head_only = m && !strcmp(m, "HEAD");
        int rc = srv_conn_send(c, hb, h);
        if (!rc && !head_only && nb) {
            if (e->flags & RS_F_CHUNKED) {
                char cs[32]; int k = snprintf(cs, sizeof cs, "%x\r\n", (unsigned)nb);
                rc = srv_conn_send(c, cs, k);
                if (!rc) rc = srv_conn_send(c, body, nb);
                if (!rc) rc = srv_conn_send(c, "\r\n0\r\n\r\n", 7);
            } else rc = srv_conn_send(c, body, nb);
        } else if (!rc && !head_only && (e->flags & RS_F_CHUNKED)) rc = srv_conn_send(c, "0\r\n\r\n", 5);
        free(hb); free(big);
        if (rc) return -1;
        if (e->flags & (RS_F_CLOSE | RS_F_NOLEN)) return -1;
    }
    return -1;
}

static const srv_step g_router_steps[] = { S_CALL(router_fn) };
static const srv_script g_router_script[] = { SRV_SCRIPT(g_router_steps) };

srv *rs_start(rs_router *r, srv_kind kind) {
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = kind; cfg.scripts = g_router_script; cfg.nscripts = 1; cfg.user = r;
    cfg.cert_profile = SRV_CERT_LOCALHOST; cfg.lifetime_ms = 30000;
    /* wininet pools idle keep-alive sockets after the handles close and shutdown() does not wake a blocked recv,
     * so with the default 5 s io timeout every srv_stop waited out its 3 s join (Win10 boot rs2: 145 tests in 400 s).
     * Every leg of a test is milliseconds apart, so a short idle timeout is safe. */
    cfg.io_timeout_ms = kind == SRV_HTTP ? 1000 : 2000;
    srv *s = NULL;
    /* r->s must be set before the first request arrives: srv_start returns accepting, so publish via a temp */
    if (srv_start(&cfg, &s) != SRV_OK) return NULL;
    r->s = s;
    return s;
}

srv *rs_plain(void) {
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTP; cfg.io_timeout_ms = 1000; cfg.lifetime_ms = 30000;   /* built-in script: 200 "hello" */
    srv *s = NULL;
    if (srv_start(&cfg, &s) != SRV_OK) return NULL;
    return s;
}

const char *rs_hp(srv *s) { return srv_hostport(s); }
int rs_wait(srv *s, int want, DWORD ms) { srv_wait_requests(s, want, ms); return srv_req_count(s); }

/* ------------------------------------------------------------------ status callbacks */
rs_cb g_rs_cb;
static CRITICAL_SECTION g_cbcs; static INIT_ONCE g_cbonce = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK cbonce(PINIT_ONCE o, PVOID p, PVOID *c) { InitializeCriticalSection(&g_cbcs); return TRUE; }

static int is_string_status(DWORD st) {
    return st == INTERNET_STATUS_REDIRECT || st == INTERNET_STATUS_RESOLVING_NAME || st == INTERNET_STATUS_NAME_RESOLVED ||
           st == INTERNET_STATUS_CONNECTING_TO_SERVER || st == INTERNET_STATUS_CONNECTED_TO_SERVER;
}
static void record(DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len, int wide) {
    EnterCriticalSection(&g_cbcs);
    int i = g_rs_cb.n;
    if (i < RS_MAXCB) {
        g_rs_cb.st[i] = st; g_rs_cb.len[i] = len; g_rs_cb.ctx[i] = ctx; g_rs_cb.str[i][0] = 0; g_rs_cb.dw[i] = 0;
        if (info && len >= 4 && !is_string_status(st)) memcpy(&g_rs_cb.dw[i], info, 4);
        if (info && is_string_status(st)) {
            if (wide && (st == INTERNET_STATUS_REDIRECT || st == INTERNET_STATUS_RESOLVING_NAME)) {
                /* the W wrapper converts only RESOLVING_NAME and REDIRECT (async_callbacks EVIDENCE, W10) */
                WideCharToMultiByte(CP_ACP, 0, (const WCHAR *)info, -1, g_rs_cb.str[i], 299, NULL, NULL);
            } else {
                size_t k = 0; const char *p = (const char *)info;
                while (k < 299 && p[k]) { g_rs_cb.str[i][k] = p[k]; k++; }
                g_rs_cb.str[i][k] = 0;
            }
            g_rs_cb.str[i][299] = 0;
        }
        g_rs_cb.n++;
    }
    LeaveCriticalSection(&g_cbcs);
}
static void CALLBACK cbA(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) { record(ctx, st, info, len, 0); }
static void CALLBACK cbW(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) { record(ctx, st, info, len, 1); }

void rs_cb_install(HINTERNET hi, int wide) {
    InitOnceExecuteOnce(&g_cbonce, cbonce, NULL, NULL);
    EnterCriticalSection(&g_cbcs); memset(&g_rs_cb, 0, sizeof g_rs_cb); g_rs_cb.wide = wide; LeaveCriticalSection(&g_cbcs);
    if (wide) U(InternetSetStatusCallbackW)(hi, cbW); else U(InternetSetStatusCallbackA)(hi, cbA);
}
int rs_cb_count(DWORD st) { int k = 0; for (int i = 0; i < g_rs_cb.n; i++) if (g_rs_cb.st[i] == st) k++; return k; }
int rs_cb_index(DWORD st, int nth) { for (int i = 0; i < g_rs_cb.n; i++) if (g_rs_cb.st[i] == st && nth-- == 0) return i; return -1; }
void rs_cb_dump(void) {
    char line[2048]; size_t o = 0;
    for (int i = 0; i < g_rs_cb.n && o < sizeof line - 32; i++) o += snprintf(line + o, sizeof line - o, "%lu%s", g_rs_cb.st[i], i + 1 < g_rs_cb.n ? "," : "");
    line[sizeof line - 1] = 0;
    t_note("callbacks: %s", line);
}

/* ------------------------------------------------------------------ request helper */
const char *rs_err(DWORD e) { return e ? t_inet_errname(e) : "0"; }

DWORD rs_status(HINTERNET hr) {
    DWORD st = 0, l = sizeof st;
    if (!U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL)) return 0;
    return st;
}

void rs_collect(HINTERNET hr, rs_res *res, int read_body) {
    DWORD l;
    res->status = rs_status(hr);
    l = sizeof res->text; res->text[0] = 0;
    if (!U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_TEXT, res->text, &l, NULL)) res->text[0] = 0;
    l = sizeof res->version; res->version[0] = 0;
    if (!U(HttpQueryInfoA)(hr, HTTP_QUERY_VERSION, res->version, &l, NULL)) res->version[0] = 0;
    l = sizeof res->url; res->url[0] = 0;
    if (!U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, res->url, &l)) res->url[0] = 0;
    l = sizeof res->location; res->location[0] = 0; res->loc_err = 0;
    if (!U(HttpQueryInfoA)(hr, HTTP_QUERY_LOCATION, res->location, &l, NULL)) { res->location[0] = 0; res->loc_err = GetLastError(); }
    l = sizeof res->raw; res->raw[0] = 0;
    if (!U(HttpQueryInfoA)(hr, HTTP_QUERY_RAW_HEADERS_CRLF, res->raw, &l, NULL)) res->raw[0] = 0;
    res->nbody = 0; res->body[0] = 0; res->read_ok = 1;
    if (read_body) res->nbody = t_inet_read_all(hr, res->body, sizeof res->body, &res->read_ok);
}

BOOL rs_do(srv *s, const char *method, const char *path, const rs_opt *o, rs_res *res) {
    static const rs_opt def; if (!o) o = &def;
    memset(res, 0, sizeof *res);
    HINTERNET hi = t_inet_open(o->agent ? o->agent : "rs-agent/1.0");
    if (!hi) { res->err = GetLastError(); return FALSE; }
    if (o->cb) rs_cb_install(hi, o->cb == 2);
    DWORD fl = o->flags;
    int https = !strncmp(srv_url(s, "/"), "https", 5);
    if (https) fl |= INTERNET_FLAG_SECURE;
    HINTERNET hc = U(InternetConnectA)(hi, o->host ? o->host : "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, method, path, NULL, o->referrer, NULL, fl, 2) : NULL;
    if (!hr) { res->err = GetLastError(); t_inet_close(hi); return FALSE; }
    if (https || o->secflags) t_https_secflags(hr, o->secflags | (https ? SECURITY_FLAG_IGNORE_UNKNOWN_CA : 0));
    SetLastError(0xdeadbeef);
    res->ok = U(HttpSendRequestA)(hr, o->hdrs, o->hdrs ? (DWORD)-1 : 0, (LPVOID)o->data, o->ndata);
    res->err = res->ok ? 0 : GetLastError();
    rs_collect(hr, res, !o->no_read);
    if (o->keep_open && o->out_hreq) { *o->out_hreq = hr; if (o->out_hi) *o->out_hi = hi; return res->ok; }
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi);
    return res->ok;
}
