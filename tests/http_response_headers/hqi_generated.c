/* hqi_generated.c - model-checked responses: deterministic pseudo-random header sets (names from a pool of custom
 * and known headers in random casing, random values, random padding, duplicates, empty values), and every query
 * of each is compared against a simple model of the WinINet response store.
 * VM_TIMEOUT: 300
 *
 * The model is built only from facts already verified on Win10 and in the decomp (see EVIDENCE.md):
 *  - values are stored with leading/trailing SP/HT removed, inner whitespace kept [W10 rsp_hdr_*];
 *  - names are matched case-insensitively and kept as received in RAW_HEADERS(_CRLF), which rebuilds every line as
 *    "Name: value" in arrival order [D QueryFilteredRawHeaders, W10];
 *  - RAW_HEADERS = each line + NUL, a final NUL not counted in *len [D, W10 hqi_buf_raw_headers_nul_layout];
 *  - duplicates are kept, walked with lpdwIndex (incremented on success only) and joined with ", " by
 *    COALESCE_WITH_COMMA [D _FindHeader, _QueryCoalesced*];
 *  - the A string protocol: n + 1 bytes needed, *len = n on success, n + 1 on ERROR_INSUFFICIENT_BUFFER; W: 2(n+1)
 *    needed, 2n on success [D _CopyValueToBuffer, HttpQueryInfoW].
 * The generator never produces a header WinINet interprets for framing or state (Content-Length, Transfer-Encoding,
 * Connection, Set-Cookie, Location, *-Authenticate, Content-Encoding); the framing is fixed at the end.
 */
#include "rh.h"

static unsigned g_seed;
static unsigned rnd(void) { g_seed = g_seed * 1103515245u + 12345u; return (g_seed >> 16) & 0x7FFF; }
static unsigned rn(unsigned n) { return n ? rnd() % n : 0; }

typedef struct { const char *name; int level; } gen_name;
static const gen_name POOL[] = {
    { "X-Gen-Alpha", -1 }, { "X-Gen-Beta", -1 }, { "X-Gen-Gamma", -1 }, { "X-Gen-Delta", -1 }, { "X-Trace-Id", -1 },
    { "X-Powered-By", -1 }, { "X-Request-Id", -1 }, { "X-A", -1 }, { "X-Long-Name-For-A-Custom-Header-Field", -1 },
    { "Server", HTTP_QUERY_SERVER }, { "Etag", HTTP_QUERY_ETAG }, { "Vary", HTTP_QUERY_VARY }, { "Via", HTTP_QUERY_VIA },
    { "Warning", HTTP_QUERY_WARNING }, { "Age", HTTP_QUERY_AGE }, { "Accept-Ranges", HTTP_QUERY_ACCEPT_RANGES },
    { "Content-Language", HTTP_QUERY_CONTENT_LANGUAGE }, { "Content-Disposition", HTTP_QUERY_CONTENT_DISPOSITION },
    { "Pragma", HTTP_QUERY_PRAGMA }, { "Link", HTTP_QUERY_LINK }, { "Allow", HTTP_QUERY_ALLOW }, { "Public", HTTP_QUERY_PUBLIC },
    { "Title", HTTP_QUERY_TITLE }, { "Content-Id", HTTP_QUERY_CONTENT_ID }, { "Content-Description", HTTP_QUERY_CONTENT_DESCRIPTION },
    { "Mime-Version", HTTP_QUERY_MIME_VERSION }, { "Cost", HTTP_QUERY_COST }, { "Derived-From", HTTP_QUERY_DERIVED_FROM },
    { "Message-Id", HTTP_QUERY_MESSAGE_ID }, { "P3P", HTTP_QUERY_P3P }, { "X-Frame-Options", HTTP_QUERY_X_FRAME_OPTIONS },
    { "X-Content-Type-Options", HTTP_QUERY_X_CONTENT_TYPE_OPTIONS }, { "X-UA-Compatible", HTTP_QUERY_X_UA_COMPATIBLE },
    { "Content-Type", HTTP_QUERY_CONTENT_TYPE }, { "Cache-Control", HTTP_QUERY_CACHE_CONTROL },
};
#define NPOOL ((int)(sizeof POOL / sizeof POOL[0]))

#define GMAX 40
typedef struct { int pool; char wire_name[64]; char value[128]; } gen_hdr;
typedef struct {
    int code; char reason[40];
    gen_hdr h[GMAX]; int n;
    char resp[16384]; size_t resp_n;
    char raw_crlf[16384];
    char raw_nul[16384]; size_t raw_nul_n;
} gen_resp;

static void casing(char *dst, const char *src, int mode) {
    for (; *src; src++, dst++) {
        char ch = *src;
        if (mode == 1) { if (ch >= 'A' && ch <= 'Z') ch = (char)(ch + 32); }
        else if (mode == 2) { if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 32); }
        else if (mode == 3 && rn(2)) ch = (ch >= 'a' && ch <= 'z') ? (char)(ch - 32) : (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
        *dst = ch;
    }
    *dst = 0;
}

static void gen_value(char *v, size_t cap) {
    static const char AL[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.;=,/\"()<>@?[]{}+*&%$#!~|^`'";
    unsigned kind = rn(10), len = kind == 0 ? 0 : kind == 1 ? 1 + rn(3) : kind == 9 ? 60 + rn(60) : 1 + rn(40);
    if (len >= cap) len = (unsigned)cap - 1;
    for (unsigned i = 0; i < len; i++) {
        char ch = AL[rn(sizeof AL - 1)];
        if (i > 0 && i + 1 < len && rn(8) == 0) ch = rn(4) ? ' ' : '\t';   /* inner whitespace, never at an end */
        v[i] = ch;
    }
    v[len] = 0;
}

static const char *const PAD[] = { "", " ", "  ", "\t", " \t ", "    " };
static const struct { int code; const char *reason; } CODES[] = {
    { 200, "OK" }, { 201, "Created" }, { 202, "Accepted" }, { 203, "Non-Authoritative Information" }, { 299, "Custom Two" },
    { 404, "Not Found" }, { 410, "Gone" }, { 418, "I'm a teapot" }, { 500, "Internal Server Error" }, { 503, "Service Unavailable" },
};

static void gen_build(gen_resp *g, unsigned seed) {
    memset(g, 0, sizeof *g);
    g_seed = seed * 2654435761u + 7;
    int ci = (int)rn(sizeof CODES / sizeof CODES[0]);
    g->code = CODES[ci].code; lstrcpyA(g->reason, CODES[ci].reason);
    g->n = 3 + (int)rn(GMAX - 3);
    int favs[4]; for (int i = 0; i < 4; i++) favs[i] = (int)rn(NPOOL);   /* a few names repeat often */
    size_t k = (size_t)sprintf(g->resp, "HTTP/1.1 %d %s\r\n", g->code, g->reason);
    size_t r = (size_t)sprintf(g->raw_crlf, "HTTP/1.1 %d %s\r\n", g->code, g->reason);
    size_t z = (size_t)sprintf(g->raw_nul, "HTTP/1.1 %d %s", g->code, g->reason) + 1;
    for (int i = 0; i < g->n; i++) {
        gen_hdr *h = &g->h[i];
        h->pool = rn(3) == 0 ? favs[rn(4)] : (int)rn(NPOOL);
        casing(h->wire_name, POOL[h->pool].name, (int)rn(4));
        gen_value(h->value, sizeof h->value);
        const char *p1 = PAD[rn(6)], *p2 = h->value[0] ? PAD[rn(6)] : "";
        k += (size_t)sprintf(g->resp + k, "%s:%s%s%s\r\n", h->wire_name, p1, h->value, p2);
        r += (size_t)sprintf(g->raw_crlf + r, "%s: %s\r\n", h->wire_name, h->value);
        z += (size_t)sprintf(g->raw_nul + z, "%s: %s", h->wire_name, h->value) + 1;
    }
    static const char TAIL[] = "Content-Length: 0\r\nConnection: close\r\n";
    k += (size_t)sprintf(g->resp + k, "%s\r\n", TAIL);
    r += (size_t)sprintf(g->raw_crlf + r, "%s\r\n", TAIL);
    z += (size_t)sprintf(g->raw_nul + z, "Content-Length: 0") + 1;
    z += (size_t)sprintf(g->raw_nul + z, "Connection: close") + 1;
    g->resp_n = k; g->raw_nul_n = z;
}

/* occurrences of pool entry p, in order */
static int occ(const gen_resp *g, int p, const char **vals) {
    int n = 0;
    for (int i = 0; i < g->n; i++) if (!lstrcmpiA(POOL[g->h[i].pool].name, POOL[p].name)) vals[n++] = g->h[i].value;
    return n;
}

static int g_bad;   /* mismatches in the current response (to stop after a few) */
#define GCHK(cond, ...) do { int ok_ = !!(cond); if (!ok_) g_bad++; t_check(ok_, __FILE__, __LINE__, #cond, __VA_ARGS__); } while (0)

static void check_name(HINTERNET hr, const gen_resp *g, int p, unsigned seed, int wide) {
    const char *vals[GMAX]; int n = occ(g, p, vals);
    char qname[64]; casing(qname, POOL[p].name, (int)rn(4));
    /* walk by CUSTOM name */
    DWORD idx = 0;
    for (int i = 0; i < n; i++) {
        DWORD before = idx;
        const char *v = wide ? rh_qwc(hr, qname, 0, &idx) : rh_qac(hr, qname, 0, &idx);
        GCHK(v && !strcmp(v, vals[i]) && idx == before + 1 && rh_len == (wide ? 2u : 1u) * (DWORD)strlen(vals[i]),
             "seed %u %c custom %s[%d]: got \"%s\" len=%lu err=%lu idx=%lu want \"%s\"", seed, wide ? 'W' : 'A', qname, i,
             v ? rh_esc(v, strlen(v)) : "(fail)", rh_len, rh_err, idx, rh_esc(vals[i], strlen(vals[i])));
    }
    const char *v = wide ? rh_qwc(hr, qname, 0, &idx) : rh_qac(hr, qname, 0, &idx);
    GCHK(!v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND && idx == (DWORD)n, "seed %u %c custom %s end: err=%lu idx=%lu n=%d", seed, wide ? 'W' : 'A', qname, rh_err, idx, n);
    /* walk by level */
    if (POOL[p].level >= 0) {
        idx = 0;
        for (int i = 0; i < n; i++) {
            v = wide ? rh_qw(hr, (DWORD)POOL[p].level, &idx) : rh_qa(hr, (DWORD)POOL[p].level, &idx);
            GCHK(v && !strcmp(v, vals[i]) && idx == (DWORD)i + 1, "seed %u %c level %d[%d]: got \"%s\" err=%lu want \"%s\"", seed, wide ? 'W' : 'A',
                 POOL[p].level, i, v ? rh_esc(v, strlen(v)) : "(fail)", rh_err, rh_esc(vals[i], strlen(vals[i])));
        }
        v = wide ? rh_qw(hr, (DWORD)POOL[p].level, &idx) : rh_qa(hr, (DWORD)POOL[p].level, &idx);
        GCHK(!v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND && idx == (DWORD)n, "seed %u level %d end err=%lu idx=%lu", seed, POOL[p].level, rh_err, idx);
    }
    /* coalesce */
    char joined[8192]; size_t jn = 0; joined[0] = 0;
    for (int i = 0; i < n; i++) jn += (size_t)sprintf(joined + jn, "%s%s", i ? ", " : "", vals[i]);
    v = wide ? rh_qwc(hr, qname, HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL) : rh_qac(hr, qname, HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL);
    GCHK(v && !strcmp(v, joined) && rh_len == (wide ? 2u : 1u) * (DWORD)jn, "seed %u %c coalesce %s: got \"%s\" len=%lu want \"%s\"", seed, wide ? 'W' : 'A', qname,
         v ? rh_esc(v, strlen(v)) : "(fail)", rh_len, rh_esc(joined, jn));
    /* buffer protocol on the first value (A: exact-1 and exact) */
    if (!wide) {
        DWORD len0 = (DWORD)strlen(vals[0]);
        char b[256]; lstrcpyA(b, qname); idx = 0;
        BOOL ok = rh_callA(hr, HTTP_QUERY_CUSTOM, b, len0, &idx);
        GCHK(!ok && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == len0 + 1 && idx == 0, "seed %u %s len %lu: ok=%d err=%lu len=%lu idx=%lu", seed, qname, len0, ok, rh_err, rh_len, idx);
        lstrcpyA(b, qname);
        ok = rh_callA(hr, HTTP_QUERY_CUSTOM, b, len0 + 1, &idx);
        GCHK(ok && rh_len == len0 && !strcmp(b, vals[0]) && idx == 1, "seed %u %s len %lu+1: ok=%d err=%lu len=%lu idx=%lu", seed, qname, len0, ok, rh_err, rh_len, idx);
    }
}

static void run_seed(unsigned seed, int wide) {
    static gen_resp g;
    gen_build(&g, seed);
    rh_t c;
    if (!rh_raw(&c, "GET", g.resp, g.resp_n)) return;
    if (!c.sent) { CHECKF(0, "seed %u send err=%lu", seed, c.err); rh_close(&c); return; }
    g_bad = 0;
    DWORD code = 0; BOOL okc = rh_qnum(c.hr, HTTP_QUERY_STATUS_CODE, &code);
    GCHK(okc && code == (DWORD)g.code, "seed %u code %lu want %d", seed, code, g.code);
    const char *st = rh_qa(c.hr, HTTP_QUERY_STATUS_TEXT, NULL);
    GCHK(st && !strcmp(st, g.reason), "seed %u reason %s", seed, st ? st : "(fail)");
    const char *raw = wide ? rh_qw(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL) : rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    GCHK(raw && !strcmp(raw, g.raw_crlf) && rh_len == (wide ? 2u : 1u) * (DWORD)strlen(g.raw_crlf), "seed %u %c raw crlf len=%lu:\n got %s\nwant %s", seed, wide ? 'W' : 'A',
         rh_len, raw ? rh_esc(raw, strlen(raw)) : "(fail)", rh_esc(g.raw_crlf, strlen(g.raw_crlf)));
    if (!wide) {
        static char nb[16384]; memset(nb, 'Z', sizeof nb);
        BOOL ok = rh_callA(c.hr, HTTP_QUERY_RAW_HEADERS, nb, sizeof nb, NULL);
        GCHK(ok && rh_len == g.raw_nul_n && !memcmp(nb, g.raw_nul, g.raw_nul_n) && nb[g.raw_nul_n] == 0,
             "seed %u raw nul ok=%d len=%lu want %u: %s", seed, ok, rh_len, (unsigned)g.raw_nul_n, rh_esc(nb, g.raw_nul_n + 1));
    }
    int seen[NPOOL] = { 0 };
    for (int i = 0; i < g.n && g_bad < 6; i++) {
        int p = g.h[i].pool;
        if (seen[p]) continue;
        seen[p] = 1;
        check_name(c.hr, &g, p, seed, wide);
    }
    /* pool names that are absent */
    for (int p = 0; p < NPOOL && g_bad < 6; p++) {
        if (seen[p]) continue;
        const char *v = rh_qac(c.hr, POOL[p].name, 0, NULL);
        GCHK(!v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND, "seed %u absent %s: %s err=%lu", seed, POOL[p].name, v ? v : "(fail)", rh_err);
        if (POOL[p].level >= 0) {
            v = rh_qa(c.hr, (DWORD)POOL[p].level, NULL);
            GCHK(!v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND, "seed %u absent level %d err=%lu", seed, POOL[p].level, rh_err);
        }
    }
    if (g_bad) t_note("seed %u response: %s", seed, rh_esc(g.resp, g.resp_n));
    rh_close(&c);
}

static void run_range(unsigned from, unsigned to, int wide) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    int fails_before = 0;
    for (unsigned s = from; s < to; s++) run_seed(s, wide);
    (void)fails_before;
}
TEST(hqi_gen_seeds_000_040_a) { run_range(0, 40, 0); }
TEST(hqi_gen_seeds_040_080_a) { run_range(40, 80, 0); }
TEST(hqi_gen_seeds_080_120_a) { run_range(80, 120, 0); }
TEST(hqi_gen_seeds_000_040_w) { run_range(0, 40, 1); }
TEST(hqi_gen_seeds_040_080_w) { run_range(40, 80, 1); }

/* the same generated header sets, all in one response, with the same name repeated up to 40 times */
TEST(hqi_gen_single_name_repeated) {
    REQUIRE(U(HttpQueryInfoA));
    static char resp[8192]; static char vals[40][48];
    for (int round = 0; round < 6; round++) {
        g_seed = 1000u + (unsigned)round;
        int n = 1 + (int)rn(40), p = (int)rn(NPOOL);
        size_t k = (size_t)sprintf(resp, "HTTP/1.1 200 OK\r\n");
        for (int i = 0; i < n; i++) {
            gen_value(vals[i], sizeof vals[i]);
            char nm[64]; casing(nm, POOL[p].name, (int)rn(4));
            k += (size_t)sprintf(resp + k, "%s: %s\r\n", nm, vals[i]);
        }
        k += (size_t)sprintf(resp + k, "Content-Length: 0\r\nConnection: close\r\n\r\n");
        rh_t c; if (!rh_raw(&c, "GET", resp, k)) return;
        if (!c.sent) { CHECKF(0, "round %d err=%lu", round, c.err); rh_close(&c); continue; }
        DWORD idx;
        /* direct access by index, backwards */
        for (int i = n - 1; i >= 0; i--) {
            idx = (DWORD)i; const char *v = rh_qac(c.hr, POOL[p].name, 0, &idx);
            CHECKF(v && !strcmp(v, vals[i]) && idx == (DWORD)i + 1, "round %d %s[%d]: \"%s\" idx=%lu want \"%s\"", round, POOL[p].name, i, v ? v : "(fail)", idx, vals[i]);
        }
        idx = (DWORD)n; const char *v = rh_qac(c.hr, POOL[p].name, 0, &idx);
        CHECKF(!v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND && idx == (DWORD)n, "round %d past end err=%lu idx=%lu", round, rh_err, idx);
        idx = 0xFFFFFFFF; v = rh_qac(c.hr, POOL[p].name, 0, &idx);
        CHECKF(!v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND && idx == 0xFFFFFFFF, "round %d idx -1 err=%lu idx=%lu", round, rh_err, idx);
        if (POOL[p].level >= 0) {
            idx = (DWORD)(n / 2); v = rh_qa(c.hr, (DWORD)POOL[p].level, &idx);
            CHECKF(v && !strcmp(v, vals[n / 2]) && idx == (DWORD)(n / 2) + 1, "round %d level %d mid", round, POOL[p].level);
        }
        rh_close(&c);
    }
}
