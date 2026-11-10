/* http_auth helpers: hashing, auth-param parsing, the gate server, the client helper. See auth.h. */
#include "auth.h"
#include <stdlib.h>
#include <ctype.h>

/* ------------------------------------------------------------------ MD5 / MD4 (RFC 1321 / RFC 1320) */
#define ROL(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
typedef struct { unsigned a, b, c, d; unsigned long long len; unsigned char buf[64]; size_t nb; int md4; } hctx;
static void md5_block(hctx *h, const unsigned char *p) {
    static const unsigned K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
    static const int R[64] = { 7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22, 5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
                               4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23, 6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
    unsigned w[16]; for (int i = 0; i < 16; i++) w[i] = p[i*4] | p[i*4+1] << 8 | p[i*4+2] << 16 | (unsigned)p[i*4+3] << 24;
    unsigned a = h->a, b = h->b, c = h->c, d = h->d;
    for (int i = 0; i < 64; i++) {
        unsigned f; int g;
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
        else { f = c ^ (b | ~d); g = (7 * i) % 16; }
        unsigned t = d; d = c; c = b; b = b + ROL(a + f + K[i] + w[g], R[i]); a = t;
    }
    h->a += a; h->b += b; h->c += c; h->d += d;
}
static void md4_block(hctx *h, const unsigned char *p) {
    unsigned x[16]; for (int i = 0; i < 16; i++) x[i] = p[i*4] | p[i*4+1] << 8 | p[i*4+2] << 16 | (unsigned)p[i*4+3] << 24;
    unsigned a = h->a, b = h->b, c = h->c, d = h->d;
#define F4(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define G4(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H4(x,y,z) ((x) ^ (y) ^ (z))
    static const int s1[4] = {3,7,11,19}, s2[4] = {3,5,9,13}, s3[4] = {3,9,11,15};
    for (int i = 0; i < 16; i++) { unsigned t = a + F4(b,c,d) + x[i]; t = ROL(t, s1[i%4]); a = d; d = c; c = b; b = t; }
    for (int i = 0; i < 16; i++) { int k = (i % 4) * 4 + i / 4; unsigned t = a + G4(b,c,d) + x[k] + 0x5a827999; t = ROL(t, s2[i%4]); a = d; d = c; c = b; b = t; }
    static const int o3[16] = {0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15};
    for (int i = 0; i < 16; i++) { unsigned t = a + H4(b,c,d) + x[o3[i]] + 0x6ed9eba1; t = ROL(t, s3[i%4]); a = d; d = c; c = b; b = t; }
    h->a += a; h->b += b; h->c += c; h->d += d;
}
static void h_init(hctx *h, int md4) { h->a = 0x67452301; h->b = 0xefcdab89; h->c = 0x98badcfe; h->d = 0x10325476; h->len = 0; h->nb = 0; h->md4 = md4; }
static void h_upd(hctx *h, const void *pv, size_t n) {
    const unsigned char *p = pv; h->len += n;
    while (n) { size_t k = 64 - h->nb; if (k > n) k = n; memcpy(h->buf + h->nb, p, k); h->nb += k; p += k; n -= k;
        if (h->nb == 64) { if (h->md4) md4_block(h, h->buf); else md5_block(h, h->buf); h->nb = 0; } }
}
static void h_fin(hctx *h, unsigned char out[16]) {
    unsigned long long bits = h->len * 8; unsigned char pad = 0x80, z = 0;
    h_upd(h, &pad, 1); while (h->nb != 56) h_upd(h, &z, 1);
    unsigned char lb[8]; for (int i = 0; i < 8; i++) lb[i] = (unsigned char)(bits >> (8 * i));
    h_upd(h, lb, 8);
    unsigned v[4] = { h->a, h->b, h->c, h->d };
    for (int i = 0; i < 16; i++) out[i] = (unsigned char)(v[i / 4] >> (8 * (i % 4)));
}
void a_md5(const void *p, size_t n, unsigned char out[16]) { hctx h; h_init(&h, 0); h_upd(&h, p, n); h_fin(&h, out); }
void a_md4(const void *p, size_t n, unsigned char out[16]) { hctx h; h_init(&h, 1); h_upd(&h, p, n); h_fin(&h, out); }
void a_hmac_md5(const void *key, size_t kn, const void *p, size_t n, unsigned char out[16]) {
    unsigned char k[64] = {0}, ip[64], op[64], inner[16];
    if (kn > 64) { a_md5(key, kn, k); kn = 16; } else memcpy(k, key, kn);
    for (int i = 0; i < 64; i++) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
    hctx h; h_init(&h, 0); h_upd(&h, ip, 64); h_upd(&h, p, n); h_fin(&h, inner);
    h_init(&h, 0); h_upd(&h, op, 64); h_upd(&h, inner, 16); h_fin(&h, out);
}
void a_hex(const unsigned char *p, size_t n, char *out) { static const char hx[] = "0123456789abcdef"; for (size_t i = 0; i < n; i++) { out[2*i] = hx[p[i] >> 4]; out[2*i+1] = hx[p[i] & 15]; } out[2*n] = 0; }
void a_md5_hex(const char *s, char out[33]) { unsigned char d[16]; a_md5(s, strlen(s), d); a_hex(d, 16, out); }
char *a_b64s(const char *s) { return srv_b64(s, strlen(s)); }

const char *a_basic(const char *user, const char *pass) {
    static char bufs[8][512]; static LONG k; char *o = bufs[InterlockedIncrement(&k) & 7];
    char t[400]; snprintf(t, sizeof t, "%s:%s", user ? user : "", pass ? pass : "");
    char *b = a_b64s(t); snprintf(o, 512, "Basic %s", b); free(b); return o;
}

/* ------------------------------------------------------------------ auth-param parsing */
static const char *skip_ws(const char *p) { while (*p == ' ' || *p == '\t' || *p == ',') p++; return p; }
int a_param(const char *hv, const char *name, char *out, size_t cap) {
    if (!hv) return 0;
    const char *p = hv; while (*p && *p != ' ') p++;   /* skip the scheme word */
    size_t nl = strlen(name);
    while (*p) {
        p = skip_ws(p); if (!*p) break;
        const char *k = p; while (*p && *p != '=' && *p != ',' && *p != ' ') p++;
        size_t kl = (size_t)(p - k);
        while (*p == ' ') p++;
        if (*p != '=') continue;
        p++; while (*p == ' ') p++;
        char v[1024]; size_t vn = 0;
        if (*p == '"') { p++; while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; if (vn + 1 < sizeof v) v[vn++] = *p; p++; } if (*p == '"') p++; }
        else { while (*p && *p != ',' && *p != ' ') { if (vn + 1 < sizeof v) v[vn++] = *p; p++; } }
        v[vn] = 0;
        if (kl == nl && !_strnicmp(k, name, nl)) { snprintf(out, cap, "%s", v); return 1; }
    }
    return 0;
}
int a_param_count(const char *hv) {
    if (!hv) return 0;
    const char *p = hv; while (*p && *p != ' ') p++;
    int n = 0, inq = 0, any = 0;
    for (; *p; p++) { if (*p == '"') inq = !inq; else if (*p == ',' && !inq) { if (any) n++; any = 0; } else if (*p != ' ') any = 1; }
    return n + any;
}

void a_digest_response(const char *user, const char *realm, const char *pass, const char *method, const char *uri,
                       const char *nonce, const char *nc, const char *cnonce, const char *qop, int sess, char out[33]) {
    char t[2048], ha1[33], ha2[33];
    snprintf(t, sizeof t, "%s:%s:%s", user, realm, pass); a_md5_hex(t, ha1);
    if (sess) { snprintf(t, sizeof t, "%s:%s:%s", ha1, nonce, cnonce); a_md5_hex(t, ha1); }
    snprintf(t, sizeof t, "%s:%s", method, uri); a_md5_hex(t, ha2);
    if (qop && *qop) snprintf(t, sizeof t, "%s:%s:%s:%s:%s:%s", ha1, nonce, nc, cnonce, qop, ha2);
    else snprintf(t, sizeof t, "%s:%s:%s", ha1, nonce, ha2);
    a_md5_hex(t, out);
}

/* ------------------------------------------------------------------ NTLM (server side, custom) */
static void put16(unsigned char *p, unsigned v) { p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); }
static void put32(unsigned char *p, unsigned v) { put16(p, v & 0xffff); put16(p + 2, v >> 16); }
static unsigned get16(const unsigned char *p) { return p[0] | p[1] << 8; }
static unsigned get32(const unsigned char *p) { return get16(p) | get16(p + 2) << 16; }
static size_t utf16(const char *s, unsigned char *out) { size_t n = 0; for (; *s; s++) { out[n++] = (unsigned char)*s; out[n++] = 0; } return n; }
static void from16(const unsigned char *p, size_t n, char *out, size_t cap) { size_t k = 0; for (size_t i = 0; i + 1 < n && k + 1 < cap; i += 2) out[k++] = p[i] ? (char)p[i] : '?'; out[k] = 0; }
static const unsigned char NTLM_CHALLENGE[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
#define NTLM_T2_FLAGS 0xE2898215u
static size_t ntlm_type2(unsigned char *m) {
    unsigned char tn[64], ti[512]; size_t tnl = utf16("I7DOM", tn), til = 0;
    struct { unsigned id; const char *v; } av[] = { { 2, "I7DOM" }, { 1, "I7SRV" }, { 4, "i7dom.test" }, { 3, "i7srv.i7dom.test" } };
    for (int i = 0; i < 4; i++) { unsigned char w[128]; size_t wl = utf16(av[i].v, w); put16(ti + til, av[i].id); put16(ti + til + 2, (unsigned)wl); memcpy(ti + til + 4, w, wl); til += 4 + wl; }
    FILETIME ft; GetSystemTimeAsFileTime(&ft); put16(ti + til, 7); put16(ti + til + 2, 8); put32(ti + til + 4, ft.dwLowDateTime); put32(ti + til + 8, ft.dwHighDateTime); til += 12;
    put16(ti + til, 0); put16(ti + til + 2, 0); til += 4;
    memset(m, 0, 56); memcpy(m, "NTLMSSP\0", 8); put32(m + 8, 2);
    put16(m + 12, (unsigned)tnl); put16(m + 14, (unsigned)tnl); put32(m + 16, 56);
    put32(m + 20, NTLM_T2_FLAGS); memcpy(m + 24, NTLM_CHALLENGE, 8);
    put16(m + 40, (unsigned)til); put16(m + 42, (unsigned)til); put32(m + 44, (unsigned)(56 + tnl));
    m[48] = 10; m[49] = 0; put16(m + 50, 19041); m[55] = 15;
    memcpy(m + 56, tn, tnl); memcpy(m + 56 + tnl, ti, til);
    return 56 + tnl + til;
}
static int ntlm_type3_check(gate *g, const unsigned char *m, size_t n) {
    if (n < 64 || memcmp(m, "NTLMSSP\0", 8) || get32(m + 8) != 3) return 0;
    memcpy(g->ntlm_type3, m, n < sizeof g->ntlm_type3 ? n : sizeof g->ntlm_type3); g->ntlm_type3_len = n;
    unsigned ntl = get16(m + 20), nto = get32(m + 24), dl = get16(m + 28), dof = get32(m + 32), ul = get16(m + 36), uo = get32(m + 40), wl = get16(m + 44), wo = get32(m + 48);
    if (nto + ntl > n || dof + dl > n || uo + ul > n || wo + wl > n) return 0;
    from16(m + dof, dl, g->ntlm_domain, sizeof g->ntlm_domain); from16(m + uo, ul, g->ntlm_user, sizeof g->ntlm_user); from16(m + wo, wl, g->ntlm_ws, sizeof g->ntlm_ws);
    if (ntl < 24 + 16 || !g->pass) return 0;
    /* NTOWFv2 = HMAC_MD5(MD4(UNICODE(pass)), UNICODE(UPPER(user) + domain)) with user/domain exactly as sent */
    unsigned char pw[512], nt[16], ud[512], k2[16], proof[16]; size_t pl = utf16(g->pass, pw);
    a_md4(pw, pl, nt);
    size_t udl = 0;
    for (unsigned i = 0; i + 1 < ul && udl + 2 < sizeof ud; i += 2) { unsigned ch = get16(m + uo + i); if (ch >= 'a' && ch <= 'z') ch -= 32; put16(ud + udl, ch); udl += 2; }
    if (udl + dl > sizeof ud) return 0;
    memcpy(ud + udl, m + dof, dl); udl += dl;
    a_hmac_md5(nt, 16, ud, udl, k2);
    size_t bl = ntl - 16; unsigned char *buf = malloc(8 + bl); memcpy(buf, NTLM_CHALLENGE, 8); memcpy(buf + 8, m + nto + 16, bl);
    a_hmac_md5(k2, 16, buf, 8 + bl, proof); free(buf);
    g->ntlm_v2_ok = !memcmp(proof, m + nto, 16);
    return g->ntlm_v2_ok;
}

/* ------------------------------------------------------------------ gate server */
int gate_fn(srv_conn *c, const srv_step *st, void *user) {
    gate *g = user; srv *s = srv_conn_server(c);
    int code = g->code ? g->code : 401;
    const char *hname = code == 407 ? "Proxy-Authorization" : "Authorization";
    const char *chname = code == 407 ? "Proxy-Authenticate" : "WWW-Authenticate";
    for (int iter = 0; iter < 64; iter++) {
        int ri = srv_conn_recv_head(c); if (ri < 0) return -1;
        InterlockedIncrement(&g->n_req);
        const char *hv = srv_req_header(s, ri, hname);
        int okv = 0;
        for (int i = 0; i < 4 && g->accept[i]; i++) if (hv && !strcmp(hv, g->accept[i])) okv = 1;
        if (!okv && hv && g->verify) okv = g->verify(g, s, ri, hv);
        const char *meth = srv_req_method(s, ri); int is_head = meth && !strcmp(meth, "HEAD");
        if (g->ntlm_mode && !okv) {
            /* NTLM legs: no header / not NTLM -> plain challenge; type1 -> type2; type3 -> verify */
            if (hv && !_strnicmp(hv, "NTLM ", 5)) {
                size_t tl; unsigned char *tok = srv_unb64(hv + 5, &tl);
                if (tok && tl >= 12 && !memcmp(tok, "NTLMSSP\0", 8) && get32(tok + 8) == 1) {
                    g->ntlm_type1_flags = tl >= 16 ? get32(tok + 12) : 0;
                    unsigned char t2[1024]; size_t t2l = ntlm_type2(t2); char *b = srv_b64(t2, t2l);
                    srv_conn_sendf(c, "HTTP/1.1 %d %s\r\n%s: NTLM %s\r\nContent-Length: 0\r\n\r\n", code, code == 407 ? "Proxy Authentication Required" : "Unauthorized", chname, b);
                    free(b); free(tok); continue;
                }
                if (tok && tl >= 12 && !memcmp(tok, "NTLMSSP\0", 8) && get32(tok + 8) == 3) okv = ntlm_type3_check(g, tok, tl);
                free(tok);
            }
        }
        if (okv) {
            InterlockedIncrement(&g->n_ok);
            const char *b = g->ok_body ? g->ok_body : "ok";
            srv_conn_sendf(c, "HTTP/1.1 200 OK\r\n%sContent-Length: %u\r\n%s\r\n%s", g->ok_hdrs ? g->ok_hdrs : "", (unsigned)strlen(b),
                           g->close_on_ok ? "Connection: close\r\n" : "", is_head ? "" : b);
            if (g->close_on_ok) return -1;
        } else {
            LONG nd = InterlockedIncrement(&g->n_deny);
            const char *b = g->deny_body ? g->deny_body : "denied";
            if (g->deny_403_after > 0 && nd > g->deny_403_after) {
                srv_conn_sendf(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\n%s", is_head ? "" : "forbidden");
                continue;
            }
            srv_conn_sendf(c, "HTTP/1.1 %d %s\r\n%sContent-Length: %u\r\n%s\r\n%s", code, code == 407 ? "Proxy Authentication Required" : "Unauthorized",
                           g->challenge ? g->challenge : "", (unsigned)strlen(b), g->close_on_deny ? "Connection: close\r\n" : "", is_head ? "" : b);
            if (g->close_on_deny) return -1;
        }
    }
    return -1;
}
srv *gate_start(gate *g) {
    static const srv_step st[] = { S_CALL(gate_fn) };
    static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; cfg.user = g; cfg.lifetime_ms = 30000;
    srv *s = NULL; if (srv_start(&cfg, &s)) return NULL; return s;
}

/* ------------------------------------------------------------------ client */
HINTERNET a_connect(HINTERNET hi, srv *s, const char *user, const char *pass) {
    return U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), user, pass, INTERNET_SERVICE_HTTP, 0, 0);
}
DWORD a_status(HINTERNET hr) { DWORD code = 0, l = sizeof code; if (!U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &code, &l, NULL)) return 0; return code; }
int a_query(HINTERNET hr, DWORD what, DWORD *index, char *buf, DWORD cap) { DWORD l = cap; buf[0] = 0; return U(HttpQueryInfoA)(hr, what, buf, &l, index) != 0; }
int a_qopt(HINTERNET h, DWORD opt, char *buf, DWORD cap, DWORD *len) { DWORD l = cap; buf[0] = 0; int ok = U(InternetQueryOptionA)(h, opt, buf, &l) != 0; if (len) *len = l; return ok; }
void a_close(HINTERNET h) { if (h) U(InternetCloseHandle)(h); }
static void setstr(HINTERNET h, DWORD opt, const char *v) { if (v) { BOOL ok = U(InternetSetOptionA)(h, opt, (void *)v, (DWORD)strlen(v)); if (!ok) t_note("set option %lu failed: %lu", opt, GetLastError()); } }
void a_send(HINTERNET hc, const areq *q, ares *r, int keep) {
    memset(r, 0, sizeof *r);
    DWORD fl = q->no_flags ? 0 : (q->flags ? q->flags : T_INET_FRESH);
    HINTERNET hr = U(HttpOpenRequestA)(hc, q->verb ? q->verb : "GET", q->path ? q->path : "/", NULL, NULL, NULL, fl, 0);
    if (!hr) { r->err = GetLastError(); return; }
    setstr(hr, INTERNET_OPTION_USERNAME, q->ruser); setstr(hr, INTERNET_OPTION_PASSWORD, q->rpass);
    setstr(hr, INTERNET_OPTION_PROXY_USERNAME, q->puser); setstr(hr, INTERNET_OPTION_PROXY_PASSWORD, q->ppass);
    SetLastError(0xdeadbeef);
    r->ok = U(HttpSendRequestA)(hr, q->hdrs, q->hdrs ? (DWORD)-1 : 0, (void *)q->body, q->body_len);
    r->err = r->ok ? 0 : GetLastError();
    r->status = a_status(hr);
    if (r->ok) r->n = t_inet_read_all(hr, r->body, sizeof r->body, NULL);
    if (keep) r->hr = hr; else a_close(hr);
}
void a_once(srv *s, const areq *q, ares *r) {
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = hi ? a_connect(hi, s, q->cuser, q->cpass) : NULL;
    if (!hc) { memset(r, 0, sizeof *r); r->err = GetLastError(); a_close(hi); return; }
    a_send(hc, q, r, 0);
    a_close(hc); t_inet_close(hi);
}
void a_dump(srv *s) {
    int n = srv_req_count(s);
    for (int i = 0; i < n; i++) {
        const char *a = REQ_AUTH(s, i), *p = REQ_PAUTH(s, i);
        t_note("req %d conn %d [%s] auth=%.80s%s pauth=%.60s", i, srv_req_conn(s, i), srv_req_line(s, i), a ? a : "(none)", a && strlen(a) > 80 ? "..." : "", p ? p : "(none)");
    }
}
