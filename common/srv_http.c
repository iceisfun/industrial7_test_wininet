/* srv_http.c - connection IO, request parsing and the script engine (HTTP and HTTPS share it). */
#include "srv_int.h"

#define SRV_MAX_HEAD  (256 * 1024)
#define SRV_MAX_BODY  (64u * 1024 * 1024)

/* ------------------------------------------------------------------ raw/plain IO */
int srv_raw_recv(srv_conn *c, char *p, int n) {
    int r = SWS.recv(c->sock, p, n, 0);
    if (r < 0) {
        int e = SWS.WSAGetLastError();
        if (c->s->stop) srv_recordf(c->s, SRV_EV_ERROR, c->id, "recv aborted by srv_stop (wsa %d)", e);
        else if (e == WSAETIMEDOUT) srv_recordf(c->s, SRV_EV_TIMEOUT, c->id, "recv timeout");
        else if (e == WSAECONNRESET || e == WSAECONNABORTED) srv_recordf(c->s, SRV_EV_RESET, c->id, "recv wsa %d", e);
        else srv_recordf(c->s, SRV_EV_ERROR, c->id, "recv wsa %d", e);
    }
    return r;
}
static int raw_send(srv_conn *c, const char *p, size_t n) {
    while (n) {
        int k = SWS.send(c->sock, p, n > 65536 ? 65536 : (int)n, 0);
        if (k <= 0) { srv_recordf(c->s, SRV_EV_ERROR, c->id, "send wsa %d", SWS.WSAGetLastError()); return -1; }
        p += k; n -= k;
    }
    return 0;
}
int srv_tls_send(srv_conn *c, const void *p, size_t n);
int srv_tls_fill(srv_conn *c);

void srv_io_reserve(srv_conn *c, size_t more) {
    if (c->nin + more + 1 > c->capin) {
        size_t cap = c->capin ? c->capin : 16384;
        while (cap < c->nin + more + 1) cap *= 2;
        c->in = realloc(c->in, cap); c->capin = cap;
    }
}
int srv_io_send(srv_conn *c, const void *p, size_t n) {
    if (c->sock == INVALID_SOCKET) return -1;
    int r = c->tls ? srv_tls_send(c, p, n) : raw_send(c, p, n);
    return r;
}
int srv_io_fill(srv_conn *c) {
    if (c->eof || c->sock == INVALID_SOCKET) return 0;
    if (c->tls) { int r = srv_tls_fill(c); if (r == 0) c->eof = 1; return r; }
    srv_io_reserve(c, 16384);
    int r = srv_raw_recv(c, c->in + c->nin, 16384);
    if (r > 0) { c->nin += r; c->in[c->nin] = 0; return r; }
    if (r == 0) c->eof = 1;
    return r;
}
void srv_io_consume(srv_conn *c, size_t n) {
    if (n >= c->nin) c->nin = 0; else { memmove(c->in, c->in + n, c->nin - n); c->nin -= n; }
    if (c->in) c->in[c->nin] = 0;
}
static int need(srv_conn *c, size_t k) {
    while (c->nin < k) if (srv_io_fill(c) <= 0) return 0;
    return 1;
}
/* index of the first '\n' (filling as needed), -1 on EOF / line > limit */
static long find_lf(srv_conn *c, size_t limit) {
    size_t scan = 0;
    for (;;) {
        for (; scan < c->nin; scan++) if (c->in[scan] == '\n') return (long)scan;
        if (c->nin > limit) return -1;
        if (srv_io_fill(c) <= 0) return -1;
    }
}

/* ------------------------------------------------------------------ request parsing */
static char *dupn(const char *p, size_t n) { char *d = malloc(n + 1); memcpy(d, p, n); d[n] = 0; return d; }
static char *trimdup(const char *p, size_t n) {
    while (n && (*p == ' ' || *p == '\t')) { p++; n--; }
    while (n && (p[n - 1] == ' ' || p[n - 1] == '\t' || p[n - 1] == '\r')) n--;
    return dupn(p, n);
}
static srv_req *parse_head(const char *h, size_t n) {
    srv_req *r = calloc(1, sizeof *r);
    r->head = dupn(h, n); r->nhead = n;
    const char *p = h, *end = h + n;
    const char *eol = memchr(p, '\n', end - p); if (!eol) eol = end;
    r->line = trimdup(p, eol - p);
    { const char *sp = strchr(r->line, ' ');
      r->method = sp ? dupn(r->line, sp - r->line) : strdup(r->line);
      const char *t = sp ? sp + 1 : "", *sp2 = strchr(t, ' ');
      r->target = sp2 ? dupn(t, sp2 - t) : strdup(t); }
    p = eol < end ? eol + 1 : end;
    int cap = 0;
    while (p < end) {
        eol = memchr(p, '\n', end - p); if (!eol) eol = end;
        size_t ll = eol - p; if (ll && p[ll - 1] == '\r') ll--;
        if (!ll) break;
        if ((*p == ' ' || *p == '\t') && r->nh) {   /* obs-fold continuation */
            char *v = r->hv[r->nh - 1], *add = trimdup(p, ll);
            char *nv = malloc(strlen(v) + strlen(add) + 2); sprintf(nv, "%s %s", v, add);
            free(v); free(add); r->hv[r->nh - 1] = nv;
        } else {
            const char *colon = memchr(p, ':', ll);
            if (r->nh == cap) { cap = cap ? cap * 2 : 16; r->hn = realloc(r->hn, cap * sizeof *r->hn); r->hv = realloc(r->hv, cap * sizeof *r->hv); }
            if (colon) { r->hn[r->nh] = dupn(p, colon - p); r->hv[r->nh] = trimdup(colon + 1, ll - (colon + 1 - p)); }
            else { r->hn[r->nh] = dupn(p, ll); r->hv[r->nh] = strdup(""); }
            r->nh++;
        }
        p = eol < end ? eol + 1 : end;
    }
    return r;
}
static const char *req_hdr(srv_req *r, const char *name) {
    if (!r) return NULL;
    for (int h = 0; h < r->nh; h++) if (!_stricmp(r->hn[h], name)) return r->hv[h];
    return NULL;
}
static int contains_ci(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    for (; hay && *hay; hay++) if (!_strnicmp(hay, needle, n)) return 1;
    return 0;
}

/* read one request head; returns request index or -1 (EOF/error before a complete head) */
static int read_head(srv_conn *c) {
    srv *s = c->s;
    for (;;) {
        size_t end = 0;
        for (size_t i = 0; i < c->nin; i++) {
            if (c->in[i] != '\n') continue;
            if (i + 1 < c->nin && c->in[i + 1] == '\n') { end = i + 2; break; }
            if (i + 2 < c->nin && c->in[i + 1] == '\r' && c->in[i + 2] == '\n') { end = i + 3; break; }
        }
        if (!end && c->nin > SRV_MAX_HEAD) end = c->nin;    /* oversized: take what we have */
        if (end) {
            srv_req *r = parse_head(c->in, end); r->conn = c->id;
            srv_io_consume(c, end);
            int idx = srv_add_req(s, r);
            c->last_req = idx;
            srv_record(s, SRV_EV_HEAD, c->id, idx, r->head, r->nhead);
            return idx;
        }
        int f = srv_io_fill(c);
        if (f <= 0) {
            if (f == 0) {
                if (c->nin) srv_record(s, SRV_EV_BYTES, c->id, -1, c->in, c->nin);   /* partial head then EOF */
                srv_record(s, SRV_EV_EOF, c->id, -1, NULL, 0);
            }
            return -1;
        }
    }
}

/* read the body of request ri per its framing; 0 ok, -1 error */
static int read_body(srv_conn *c, int ri) {
    srv *s = c->s; srv_req *r = srv_get_req(s, ri);
    if (!r) return 0;
    char *body = NULL, *raw = NULL; size_t nb = 0, nr = 0; int chunked = 0, ok = 1;
    const char *te = req_hdr(r, "Transfer-Encoding"), *cl = req_hdr(r, "Content-Length");
    if (te && contains_ci(te, "chunked")) {
        chunked = 1;
        for (int guard = 0; guard < 100000; guard++) {
            long lf = find_lf(c, 4096); if (lf < 0) { ok = 0; break; }
            unsigned long long sz = strtoull(c->in, NULL, 16);
            raw = realloc(raw, nr + lf + 1); memcpy(raw + nr, c->in, lf + 1); nr += lf + 1;
            srv_io_consume(c, lf + 1);
            if (sz == 0) {   /* trailers until empty line */
                for (int t = 0; t < 64; t++) {
                    lf = find_lf(c, 8192); if (lf < 0) { ok = 0; break; }
                    raw = realloc(raw, nr + lf + 1); memcpy(raw + nr, c->in, lf + 1); nr += lf + 1;
                    int empty = lf == 0 || (lf == 1 && c->in[0] == '\r');
                    srv_io_consume(c, lf + 1);
                    if (empty) break;
                }
                break;
            }
            if (nb + sz > SRV_MAX_BODY || !need(c, sz + 2)) { ok = 0; break; }
            body = realloc(body, nb + sz + 1); memcpy(body + nb, c->in, sz); nb += sz;
            raw = realloc(raw, nr + sz + 2); memcpy(raw + nr, c->in, sz + 2); nr += sz + 2;
            srv_io_consume(c, sz + 2);
        }
    } else if (cl) {
        unsigned long long want = strtoull(cl, NULL, 10);
        if (want > SRV_MAX_BODY) want = SRV_MAX_BODY;
        body = malloc(want + 1);
        while (nb < want) {
            if (!c->nin && srv_io_fill(c) <= 0) { ok = 0; break; }
            size_t k = c->nin < want - nb ? c->nin : want - nb;
            memcpy(body + nb, c->in, k); nb += k; srv_io_consume(c, k);
        }
        raw = malloc(nb + 1); memcpy(raw, body, nb); nr = nb;
    }
    if (!body) body = malloc(1);
    if (!raw) raw = malloc(1);
    body[nb] = 0; raw[nr] = 0;
    EnterCriticalSection(&s->cs);
    r->body = body; r->nbody = nb; r->body_raw = raw; r->nbody_raw = nr; r->chunked = chunked; r->has_body = 1;
    LeaveCriticalSection(&s->cs);
    srv_record(s, SRV_EV_BODY, c->id, ri, body, nb);
    return ok ? 0 : -1;
}

/* ------------------------------------------------------------------ sending helpers */
typedef struct { char *p; size_t n, cap; } sbuf;
static void sb_add(sbuf *b, const void *p, size_t n) {
    if (b->n + n + 1 > b->cap) { b->cap = (b->n + n + 1) * 2; b->p = realloc(b->p, b->cap); }
    memcpy(b->p + b->n, p, n); b->n += n; b->p[b->n] = 0;
}
static void sb_str(sbuf *b, const char *s) { sb_add(b, s, strlen(s)); }
static void sb_fmt(sbuf *b, const char *fmt, ...) { char t[512]; va_list a; va_start(a, fmt); int n = vsnprintf(t, sizeof t, fmt, a); va_end(a); if (n > 0) sb_add(b, t, n < (int)sizeof t ? n : (int)sizeof t - 1); }

static void expand(srv_conn *c, sbuf *b, const char *in, size_t n) {
    srv_req *r = srv_get_req(c->s, c->last_req);
    for (size_t i = 0; i < n; i++) {
        if (in[i] != '%' || i + 1 >= n) { sb_add(b, in + i, 1); continue; }
        char k = in[++i];
        if (k == 'P') sb_fmt(b, "%u", c->s->port);
        else if (k == 'H') { const char *h = req_hdr(r, "Host"); sb_str(b, h ? h : ""); }
        else if (k == 'R') sb_str(b, r ? r->target : "");
        else if (k == 'S') sb_str(b, c->s->kind == SRV_HTTPS ? "https" : "http");
        else if (k == '%') sb_add(b, "%", 1);
        else { sb_add(b, "%", 1); sb_add(b, &k, 1); }
    }
}
static int send_sb(srv_conn *c, sbuf *b) {
    int r = srv_io_send(c, b->p, b->n);
    if (!r) srv_record(c->s, SRV_EV_SENT, c->id, -1, b->p, b->n > 256 ? 256 : b->n);
    return r;
}
static int send_chunked(srv_conn *c, const char *p, size_t n, size_t csz) {
    sbuf b = {0};
    if (!csz) csz = n ? n : 1;
    for (size_t off = 0; off < n; off += csz) {
        size_t k = n - off < csz ? n - off : csz;
        sb_fmt(&b, "%zx\r\n", k); sb_add(&b, p + off, k); sb_add(&b, "\r\n", 2);
    }
    sb_str(&b, "0\r\n\r\n");
    int r = srv_io_send(c, b.p, b.n); free(b.p); return r;
}
static const char *reason(int code) {
    switch (code) {
    case 100: return "Continue"; case 101: return "Switching Protocols"; case 102: return "Processing"; case 103: return "Early Hints";
    case 200: return "OK"; case 201: return "Created"; case 202: return "Accepted"; case 203: return "Non-Authoritative Information";
    case 204: return "No Content"; case 205: return "Reset Content"; case 206: return "Partial Content";
    case 300: return "Multiple Choices"; case 301: return "Moved Permanently"; case 302: return "Found"; case 303: return "See Other";
    case 304: return "Not Modified"; case 305: return "Use Proxy"; case 307: return "Temporary Redirect"; case 308: return "Permanent Redirect";
    case 400: return "Bad Request"; case 401: return "Unauthorized"; case 403: return "Forbidden"; case 404: return "Not Found";
    case 405: return "Method Not Allowed"; case 407: return "Proxy Authentication Required"; case 408: return "Request Timeout";
    case 411: return "Length Required"; case 412: return "Precondition Failed"; case 413: return "Payload Too Large";
    case 416: return "Range Not Satisfiable"; case 417: return "Expectation Failed";
    case 500: return "Internal Server Error"; case 501: return "Not Implemented"; case 502: return "Bad Gateway";
    case 503: return "Service Unavailable"; case 504: return "Gateway Timeout"; case 505: return "HTTP Version Not Supported";
    default: return "Status";
    }
}

/* returns 1 if the script must end (connection closes) */
static int do_reply(srv_conn *c, const srv_step *st) {
    int code = st->arg ? st->arg : 200;
    srv_req *r = srv_get_req(c->s, c->last_req);
    int is_head = r && !strcmp(r->method, "HEAD");
    const unsigned char *body = (const unsigned char *)st->data; size_t blen = st->data ? (st->n ? st->n : strlen(st->data)) : st->n;
    unsigned char *pat = NULL, *enc = NULL;
    if (!st->data && blen) { pat = malloc(blen); for (size_t i = 0; i < blen; i++) pat[i] = srv_pattern_byte(i); body = pat; }
    const char *ce = NULL;
    if (st->flags & (SRV_R_GZIP | SRV_R_DEFLATE | SRV_R_RAWDEFLATE)) {
        int mode = st->flags & SRV_R_GZIP ? 0 : st->flags & SRV_R_DEFLATE ? 1 : 2;
        enc = srv_deflate_stored(body, blen, mode, &blen); body = enc;
        ce = mode == 0 ? "gzip" : "deflate";
    }
    int nobody_status = code < 200 || code == 204 || code == 304;
    sbuf h = {0};
    sb_fmt(&h, "HTTP/1.%d %d %s\r\n", st->flags & SRV_R_HTTP10 ? 0 : 1, code, reason(code));
    if (st->hdrs) expand(c, &h, st->hdrs, strlen(st->hdrs));
    if (c->extra_hdr) { sb_str(&h, c->extra_hdr); free(c->extra_hdr); c->extra_hdr = NULL; }
    if (ce) sb_fmt(&h, "Content-Encoding: %s\r\n", ce);
    if (!(st->flags & (SRV_R_NO_LENGTH | SRV_R_CLOSE))) {
        if (st->flags & SRV_R_CHUNKED) sb_str(&h, "Transfer-Encoding: chunked\r\n");
        else if (!(nobody_status && !blen)) sb_fmt(&h, "Content-Length: %zu\r\n", blen);
    }
    if (st->flags & SRV_R_KEEPALIVE) sb_str(&h, "Connection: Keep-Alive\r\n");
    if (st->flags & SRV_R_CONN_CLOSE) sb_str(&h, "Connection: close\r\n");
    sb_str(&h, "\r\n");
    int rc = 0;
    if (send_sb(c, &h)) rc = 1;
    else if (!is_head || (st->flags & SRV_R_BODY_ON_HEAD)) {
        size_t send_len = st->flags & SRV_R_TRUNCATE ? blen / 2 : blen;
        if (st->flags & SRV_R_CHUNKED) { if (send_chunked(c, (const char *)body, send_len, st->n2)) rc = 1; }
        else if (send_len && srv_io_send(c, body, send_len)) rc = 1;
    }
    free(h.p); free(pat); free(enc);
    if (st->flags & (SRV_R_CLOSE | SRV_R_CONN_CLOSE | SRV_R_TRUNCATE)) rc = 1;
    return rc;
}

/* ------------------------------------------------------------------ SSPI auth (NTLM / Negotiate) */
static int do_auth(srv_conn *c, const srv_step *st) {
    srv *s = c->s; const char *pkg = st->data ? st->data : "NTLM";
    if (!srv_sspi_load()) { srv_recordf(s, SRV_EV_AUTH, c->id, "fail unavailable"); return 1; }
    WCHAR wpkg[32]; MultiByteToWideChar(CP_ACP, 0, pkg, -1, wpkg, 32);
    CredHandle cred; TimeStamp ts; CtxtHandle ctx; int have = 0, done = 0;
    SECURITY_STATUS st0 = SSP->AcquireCredentialsHandleW(NULL, wpkg, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &cred, &ts);
    if (st0 != SEC_E_OK) { srv_recordf(s, SRV_EV_AUTH, c->id, "fail acquire 0x%lx", st0); return 1; }
    size_t pl = strlen(pkg);
    for (int leg = 0; leg < 6 && !done && !s->stop; leg++) {
        int ri = read_head(c); if (ri < 0) { srv_recordf(s, SRV_EV_AUTH, c->id, "fail eof"); break; }
        read_body(c, ri);
        srv_req *r = srv_get_req(s, ri);
        const char *a = req_hdr(r, "Authorization");
        sbuf h = {0};
        if (!a || _strnicmp(a, pkg, pl) || a[pl] != ' ') {
            sb_fmt(&h, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: %s\r\nContent-Length: 0\r\n\r\n", pkg);
            send_sb(c, &h); free(h.p); continue;
        }
        size_t tl; unsigned char *tok = srv_unb64(a + pl + 1, &tl);
        if (!tok) { srv_recordf(s, SRV_EV_AUTH, c->id, "fail bad base64"); break; }
        SecBuffer ib = { (ULONG)tl, SECBUFFER_TOKEN, tok }; SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib };
        SecBuffer ob = { 0, SECBUFFER_TOKEN, NULL }; SecBufferDesc od = { SECBUFFER_VERSION, 1, &ob };
        ULONG attr;
        SECURITY_STATUS ss = SSP->AcceptSecurityContext(&cred, have ? &ctx : NULL, &id, ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONNECTION,
                                                         SECURITY_NATIVE_DREP, &ctx, &od, &attr, &ts);
        free(tok);
        if (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_OK) have = 1;
        char *ob64 = ob.cbBuffer && ob.pvBuffer ? srv_b64(ob.pvBuffer, ob.cbBuffer) : NULL;
        if (ob.pvBuffer) SSP->FreeContextBuffer(ob.pvBuffer);
        if (ss == SEC_I_CONTINUE_NEEDED) {
            sb_fmt(&h, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: %s %s\r\nContent-Length: 0\r\n\r\n", pkg, ob64 ? ob64 : "");
            send_sb(c, &h);
        } else if (ss == SEC_E_OK) {
            SecPkgContext_NamesW nm; char user[256] = "?";
            if (SSP->QueryContextAttributesW(&ctx, SECPKG_ATTR_NAMES, &nm) == SEC_E_OK) {
                WideCharToMultiByte(CP_UTF8, 0, nm.sUserName, -1, user, sizeof user, NULL, NULL); SSP->FreeContextBuffer(nm.sUserName);
            }
            srv_recordf(s, SRV_EV_AUTH, c->id, "ok %s", user);
            if (ob64) { size_t L = strlen(ob64) + pl + 32; c->extra_hdr = malloc(L); snprintf(c->extra_hdr, L, "WWW-Authenticate: %s %s\r\n", pkg, ob64); }
            done = 1;
        } else {
            srv_recordf(s, SRV_EV_AUTH, c->id, "fail 0x%lx", ss);
            sb_fmt(&h, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: %s\r\nContent-Length: 0\r\n\r\n", pkg);
            send_sb(c, &h);
            if (have) { SSP->DeleteSecurityContext(&ctx); have = 0; }
        }
        free(ob64); free(h.p);
    }
    if (have) SSP->DeleteSecurityContext(&ctx);
    SSP->FreeCredentialsHandle(&cred);
    return done ? 0 : 1;
}

/* ------------------------------------------------------------------ script engine */
static const srv_step g_default_steps[] = {
    S_HEAD(), S_BODY(), S_REPLY(200, "Content-Type: text/plain\r\n", "hello"), S_LOOP()
};
static const srv_script g_default = SRV_SCRIPT(g_default_steps);

static void do_reset(srv_conn *c) {
    srv *s = c->s;
    EnterCriticalSection(&s->cs);
    if (c->sock != INVALID_SOCKET) {
        struct linger lg = { 1, 0 }; SWS.setsockopt(c->sock, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg);
        SWS.closesocket(c->sock); c->sock = INVALID_SOCKET;
    }
    LeaveCriticalSection(&s->cs);
}

void srv_http_conn(srv_conn *c) {
    srv *s = c->s; const srv_script *sc = c->sc ? c->sc : &g_default;
    int pc = 0, jumps = 0;
    for (;;) {
        if (s->stop) break;
        if (sc->nsteps && pc >= sc->nsteps) break;
        const srv_step *st = &sc->steps[pc++];
        switch (st->op) {
        case SRV_END: goto end;
        case SRV_RECV_HEAD: {
            int ri = read_head(c); if (ri < 0) return;
            if (st->data) {
                const char *line = srv_req_line(s, ri);
                if (strncmp(line, st->data, strlen(st->data))) srv_recordf(s, SRV_EV_MISMATCH, c->id, "want [%s] got [%s]", st->data, line);
            }
            break;
        }
        case SRV_RECV_BODY: if (c->last_req >= 0 && read_body(c, c->last_req)) goto end; break;
        case SRV_RECV_BYTES: {
            size_t want = st->n; char *b = NULL; size_t nb = 0;
            if (want) { if (!need(c, want)) want = c->nin; b = malloc(want + 1); memcpy(b, c->in, want); nb = want; srv_io_consume(c, want); }
            else { while (srv_io_fill(c) > 0 && c->nin < SRV_MAX_BODY) ; b = malloc(c->nin + 1); memcpy(b, c->in, c->nin); nb = c->nin; srv_io_consume(c, c->nin); }
            srv_record(s, SRV_EV_BYTES, c->id, -1, b, nb); free(b);
            break;
        }
        case SRV_SEND: {
            size_t n = st->n ? st->n : (st->data ? strlen(st->data) : 0);
            if (srv_io_send(c, st->data, n)) goto end;
            srv_record(s, SRV_EV_SENT, c->id, -1, st->data, n > 256 ? 256 : n);
            break;
        }
        case SRV_SEND_FMT: {
            sbuf b = {0}; expand(c, &b, st->data, st->n ? st->n : strlen(st->data));
            int r = send_sb(c, &b); free(b.p); if (r) goto end; break;
        }
        case SRV_SEND_SPLIT: {
            size_t n = st->n ? st->n : strlen(st->data), piece = st->arg > 0 ? (size_t)st->arg : 1;
            DWORD ms = st->flags ? st->flags : 10; if (ms > 1000) ms = 1000;
            for (size_t off = 0; off < n; off += piece) {
                if (off && srv_wait_stop(s, ms)) goto end;
                if (srv_io_send(c, st->data + off, n - off < piece ? n - off : piece)) goto end;
            }
            break;
        }
        case SRV_SEND_CHUNKED: if (send_chunked(c, st->data, st->n ? st->n : strlen(st->data), st->arg > 0 ? st->arg : 0)) goto end; break;
        case SRV_SEND_PATTERN: {
            char buf[8192];
            for (size_t off = 0; off < st->n; off += sizeof buf) {
                size_t k = st->n - off < sizeof buf ? st->n - off : sizeof buf;
                for (size_t i = 0; i < k; i++) buf[i] = srv_pattern_byte(off + i);
                if (srv_io_send(c, buf, k)) goto end;
            }
            break;
        }
        case SRV_REPLY: if (do_reply(c, st)) goto end; break;
        case SRV_REPLY_100: {
            const char *e = req_hdr(srv_get_req(s, c->last_req), "Expect");
            if (st->arg || (e && contains_ci(e, "100-continue"))) {
                static const char m[] = "HTTP/1.1 100 Continue\r\n\r\n";
                if (srv_io_send(c, m, sizeof m - 1)) goto end;
                srv_record(s, SRV_EV_SENT, c->id, -1, m, sizeof m - 1);
            }
            break;
        }
        case SRV_SLEEP: if (srv_wait_stop(s, st->arg > 5000 ? 5000 : st->arg)) goto end; break;
        case SRV_SHUT_WR:
            if (c->tls) srv_tls_shutdown(c);
            if (c->sock != INVALID_SOCKET) SWS.shutdown(c->sock, SD_SEND);
            break;
        case SRV_RESET: srv_recordf(s, SRV_EV_SCRIPT_DONE, c->id, "reset"); do_reset(c); return;
        case SRV_CLOSE: goto end;
        case SRV_LOOP: if (++jumps > 1000) goto end; pc = st->arg; break;
        case SRV_CALL: if (!st->fn || st->fn(c, st, s->cfg.user) < 0) goto end; break;
        case SRV_AUTH_SSPI: if (do_auth(c, st)) goto end; break;
        case SRV_CLOSE_IF_ASKED: {
            srv_req *r = srv_get_req(s, c->last_req);
            if (r) {
                const char *cn = req_hdr(r, "Connection"); size_t ll = strlen(r->line);
                int v10 = ll >= 8 && !strcmp(r->line + ll - 8, "HTTP/1.0");
                if ((cn && contains_ci(cn, "close")) || (v10 && !(cn && contains_ci(cn, "keep-alive")))) goto end;
            }
            break;
        }
        default: srv_recordf(s, SRV_EV_ERROR, c->id, "bad op %d", st->op); goto end;
        }
    }
end:
    srv_recordf(s, SRV_EV_SCRIPT_DONE, c->id, "pc=%d", pc);
}

/* ------------------------------------------------------------------ public helpers for SRV_CALL */
int srv_conn_id(srv_conn *c) { return c->id; }
srv *srv_conn_server(srv_conn *c) { return c->s; }
int srv_conn_send(srv_conn *c, const void *p, size_t n) { return srv_io_send(c, p, n); }
int srv_conn_sendf(srv_conn *c, const char *fmt, ...) {
    char t[4096]; va_list a; va_start(a, fmt); int n = vsnprintf(t, sizeof t, fmt, a); va_end(a);
    if (n < 0) return -1; if (n >= (int)sizeof t) n = sizeof t - 1;
    return srv_io_send(c, t, n);
}
int srv_conn_recv_head(srv_conn *c) { int ri = read_head(c); if (ri >= 0) read_body(c, ri); return ri; }
int srv_conn_last_req(srv_conn *c) { return c->last_req; }
