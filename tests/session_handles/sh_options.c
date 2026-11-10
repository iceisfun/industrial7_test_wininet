/* session_handles / InternetQueryOption + InternetSetOption rules per handle type.
 * Table-driven: every row says, for NULL / session (Inet) / HTTP connect (HCon) / HTTP request (HReq), whether a query
 * succeeds (and with what size) or which error it gives. Evidence: [D InternetQueryOptionA@0x59730 switch,
 * IsPerProcessOption@0x53ce8, InternetSetOptionA@0x551b0], VM runs (EVIDENCE.md). */
#include "sh.h"

#define OKN(n)  (0x40000000u | (n))     /* success, *len == n (fixed size) */
#define OKS     0x60000000u             /* success, string (len == strlen) */
#define NOTE_   0x20000000u             /* record only */
enum { K_NULL, K_S, K_C, K_R, K_N };
static const char *const sh_kname[K_N] = { "NULL", "session", "connect", "request" };

typedef struct { DWORD opt; const char *name; DWORD exp[K_N]; } sh_qrow;
#define E18 ERROR_INTERNET_INCORRECT_HANDLE_TYPE
#define E16 ERROR_INTERNET_INVALID_OPERATION
static const sh_qrow sh_qtab[] = {
    { 2,  "CONNECT_TIMEOUT",        { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 3,  "CONNECT_RETRIES",        { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 4,  "CONNECT_BACKOFF",        { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 5,  "SEND_TIMEOUT",           { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 6,  "RECEIVE_TIMEOUT",        { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 7,  "DATA_SEND_TIMEOUT",      { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 8,  "DATA_RECEIVE_TIMEOUT",   { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 9,  "HANDLE_TYPE",            { E18, OKN(4), OKN(4), OKN(4) } },
    { 10, "CONTEXT_VALUE(10)",      { E18, OKN(8), OKN(8), OKN(8) } },
    { 12, "READ_BUFFER_SIZE",       { E18, E18, OKN(4), OKN(4) } },
    { 13, "WRITE_BUFFER_SIZE",      { E18, E18, OKN(4), OKN(4) } },
    { 15, "ASYNC_ID",               { ERROR_CALL_NOT_IMPLEMENTED, ERROR_CALL_NOT_IMPLEMENTED, ERROR_CALL_NOT_IMPLEMENTED, ERROR_CALL_NOT_IMPLEMENTED } },
    { 16, "ASYNC_PRIORITY",         { E18, ERROR_CALL_NOT_IMPLEMENTED, ERROR_CALL_NOT_IMPLEMENTED, ERROR_CALL_NOT_IMPLEMENTED } },
    { 21, "PARENT_HANDLE",          { E18, OKN(8), OKN(8), OKN(8) } },
    { 22, "KEEP_CONNECTION",        { E18, E18, OKN(4), E18 } },
    { 23, "REQUEST_FLAGS",          { E18, E18, E18, OKN(4) } },
    { 24, "EXTENDED_ERROR",         { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 26, "OFFLINE_MODE",           { E18, ERROR_CALL_NOT_IMPLEMENTED, ERROR_CALL_NOT_IMPLEMENTED, ERROR_CALL_NOT_IMPLEMENTED } },
    { 28, "USERNAME",               { E18, E18, OKS, OKS } },
    { 29, "PASSWORD",               { E18, E18, OKS, OKS } },
    { 30, "ASYNC",                  { E18, ERROR_CALL_NOT_IMPLEMENTED, ERROR_CALL_NOT_IMPLEMENTED, ERROR_CALL_NOT_IMPLEMENTED } },
    { 31, "SECURITY_FLAGS",         { E18, E18, E18, OKN(4) } },
    { 32, "SECURITY_CERTIFICATE_STRUCT", { E18, E18, E18, E16 } },
    { 33, "DATAFILE_NAME",          { E18, E18, E18, NOTE_ } },
    { 34, "URL",                    { E18, E18, E18, OKS } },
    { 35, "SECURITY_CERTIFICATE",   { E18, E18, E18, E16 } },
    { 36, "SECURITY_KEY_BITNESS",   { E18, E18, E18, E16 } },
    { 38, "PROXY",                  { NOTE_, NOTE_, E18, E18 } },
    { 40, "VERSION",                { OKN(8), OKN(8), OKN(8), OKN(8) } },
    { 41, "USER_AGENT",             { NOTE_, OKS, E18, E18 } },
    { 43, "PROXY_USERNAME",         { E18, E18, OKS, OKS } },
    { 44, "PROXY_PASSWORD",         { E18, E18, OKS, OKS } },
    { 45, "CONTEXT_VALUE",          { E18, OKN(8), OKN(8), OKN(8) } },
    { 50, "CONNECTED_STATE",        { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 51, "IDLE_STATE",             { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 52, "OFFLINE_SEMANTICS",      { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 53, "SECONDARY_CACHE_KEY",    { NOTE_, E18, E18, OKS } },
    { 54, "CALLBACK_FILTER",        { NOTE_, ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED } },
    { 55, "CONNECT_TIME",           { NOTE_, ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED } },
    { 56, "SEND_THROUGHPUT",        { NOTE_, ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED } },
    { 57, "RECEIVE_THROUGHPUT",     { NOTE_, ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED } },
    { 58, "REQUEST_PRIORITY",       { E18, E18, E18, OKN(4) } },
    { 59, "HTTP_VERSION",           { OKN(8), OKN(8), OKN(8), OKN(8) } },
    { 63, "FROM_CACHE_TIMEOUT",     { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 64, "BYPASS_EDITED_ENTRY",    { NOTE_, OKN(4), OKN(4), OKN(4) } },
    { 65, "HTTP_DECODING",          { E18, OKN(4), OKN(4), OKN(4) } },
    { 68, "CODEPAGE",               { NOTE_, OKN(4), OKN(4), OKN(4) } },
    { 70, "DISABLE_AUTODIAL",       { NOTE_, ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED } },
    { 73, "MAX_CONNS_PER_SERVER",   { OKN(4), E16, OKN(4), E16 } },
    { 74, "MAX_CONNS_PER_1_0_SERVER", { OKN(4), E16, E16, E16 } },
    { 82, "AUTODIAL_MODE",          { OKN(4), OKN(4), OKN(4), OKN(4) } },
    { 100, "CODEPAGE_PATH",         { NOTE_, OKN(4), OKN(4), OKN(4) } },
    { 101, "CODEPAGE_EXTRA",        { NOTE_, OKN(4), OKN(4), OKN(4) } },
    { 102, "IDN",                   { NOTE_, OKN(4), OKN(4), OKN(4) } },
    { 103, "MAX_CONNS_PER_PROXY",   { OKN(4), E16, E16, E16 } },
    { 105, "SERVER_CERT_CHAIN_CONTEXT", { NOTE_, E18, E18, NOTE_ } },
    { 0,   "option 0",              { ERROR_INTERNET_INVALID_OPTION, ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER } },
    { 193, "option 193",            { ERROR_INTERNET_INVALID_OPTION, ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER } },
    { 999, "option 999",            { ERROR_INTERNET_INVALID_OPTION, ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER } },
    { 0xffffffffu, "option -1",     { ERROR_INTERNET_INVALID_OPTION, ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER } },
};
#define SH_QN (sizeof sh_qtab / sizeof *sh_qtab)

typedef struct { HINTERNET h[K_N]; } sh_tree;
static int sh_tree_make(sh_tree *t) {
    memset(t, 0, sizeof *t);
    t->h[K_S] = sh_open("matrix-agent");
    t->h[K_C] = t->h[K_S] ? U(InternetConnectA)(t->h[K_S], "127.0.0.1", 80, "mu", "mp", INTERNET_SERVICE_HTTP, 0, 0x11) : NULL;
    t->h[K_R] = t->h[K_C] ? sh_request(t->h[K_C], "/matrix", 0x12) : NULL;
    return t->h[K_S] && t->h[K_C] && t->h[K_R];
}
static void sh_tree_free(sh_tree *t) { for (int k = K_N - 1; k >= K_S; k--) if (t->h[k]) sh_close(t->h[k]); }

static void sh_check_cell(const sh_qrow *row, int k, BOOL ok, DWORD err, DWORD len, const BYTE *buf, int wide) {
    DWORD x = row->exp[k];
    if (x == NOTE_) {
        t_note("%s query %s on %s: ok=%d err=%lu len=%lu", wide ? "W" : "A", row->name, sh_kname[k], ok, ok ? 0 : err, len);
        return;
    }
    if (x == OKS) {
        CHECKF(ok, "%s query %s on %s: err %lu (want success)", wide ? "W" : "A", row->name, sh_kname[k], err);
        if (ok && !wide) CHECKF(len == strlen((const char *)buf), "%s on %s: len %lu strlen %u", row->name, sh_kname[k], len, (unsigned)strlen((const char *)buf));
        if (ok && wide) CHECKF(len == (DWORD)lstrlenW((LPCWSTR)buf), "W %s on %s: len %lu wcslen %d", row->name, sh_kname[k], len, lstrlenW((LPCWSTR)buf));
        return;
    }
    if (x & 0x40000000u) {
        DWORD n = x & 0xffff;
        CHECKF(ok, "%s query %s on %s: err %lu (want success)", wide ? "W" : "A", row->name, sh_kname[k], err);
        if (ok) CHECKF(len == n, "%s query %s on %s: len %lu want %lu", wide ? "W" : "A", row->name, sh_kname[k], len, n);
        return;
    }
    CHECKF(!ok && err == x, "%s query %s on %s: ok=%d err %lu want %lu", wide ? "W" : "A", row->name, sh_kname[k], ok, ok ? 0 : err, x);
    /* A zeroes *len on the NULL-handle rejection; the W wrapper leaves it alone for its own string options */
    if (!wide && !ok && (err == E18 || err == ERROR_INTERNET_INVALID_OPTION) && k == K_NULL)
        CHECKF(len == 0, "%s query %s on NULL: *len %lu want 0", wide ? "W" : "A", row->name, len);
}

TEST(sh_opt_query_matrix_a) {
    REQUIRE(U(InternetQueryOptionA));
    sh_tree t; CHECK(sh_tree_make(&t));
    if (!t.h[K_R]) { sh_tree_free(&t); return; }
    for (size_t i = 0; i < SH_QN; i++) {
        for (int k = 0; k < K_N; k++) {
            static BYTE buf[2048]; memset(buf, 0, sizeof buf);
            DWORD len = sizeof buf;
            SetLastError(0xdeadbeef);
            BOOL ok = U(InternetQueryOptionA)(t.h[k], sh_qtab[i].opt, buf, &len);
            DWORD err = GetLastError();
            sh_check_cell(&sh_qtab[i], k, ok, err, len, buf, 0);
            if (ok && sh_qtab[i].exp[k] != NOTE_) CHECKF(err == 0, "A query %s on %s: GLE %lu after success", sh_qtab[i].name, sh_kname[k], err);
        }
    }
    sh_tree_free(&t);
}

TEST(sh_opt_query_matrix_w) {
    REQUIRE(U(InternetQueryOptionW));
    sh_tree t; CHECK(sh_tree_make(&t));
    if (!t.h[K_R]) { sh_tree_free(&t); return; }
    for (size_t i = 0; i < SH_QN; i++) {
        if (sh_qtab[i].opt == 38) continue;   /* PROXY has its own W layout, see sh_open_proxy_w_query */
        for (int k = 0; k < K_N; k++) {
            static BYTE buf[4096]; memset(buf, 0, sizeof buf);
            DWORD len = sizeof buf;
            SetLastError(0xdeadbeef);
            BOOL ok = U(InternetQueryOptionW)(t.h[k], sh_qtab[i].opt, buf, &len);
            sh_check_cell(&sh_qtab[i], k, ok, GetLastError(), len, buf, 1);
        }
    }
    sh_tree_free(&t);
}

/* NULL lpdwBufferLength is 87 for every handle kind (A, all options). The W wrapper converts string options
 * itself and dereferences lpdwBufferLength (Win10 access-violates for W URL with a buffer and NULL length,
 * [D InternetQueryOptionW case 0x22]), so W is only probed for options it forwards straight to A (< 0x1c). */
TEST(sh_opt_query_null_length_87) {
    sh_tree t; CHECK(sh_tree_make(&t));
    const DWORD opts[] = { 2, 9, 21, 28, 34, 41, 45, 999 };
    for (int k = 0; k < K_N; k++) for (size_t i = 0; i < sizeof opts / sizeof *opts; i++) {
        BYTE b[64];
        SetLastError(0);
        BOOL ok = U(InternetQueryOptionA)(t.h[k], opts[i], b, NULL);
        DWORD e = GetLastError();
        CHECKF(!ok && e == ERROR_INVALID_PARAMETER, "A opt %lu on %s: ok=%d err %lu", opts[i], sh_kname[k], ok, e);
        if (opts[i] >= 0x1c) continue;
        SetLastError(0);
        ok = U(InternetQueryOptionW)(t.h[k], opts[i], b, NULL);
        e = GetLastError();
        CHECKF(!ok && e == ERROR_INVALID_PARAMETER, "W opt %lu on %s: ok=%d err %lu", opts[i], sh_kname[k], ok, e);
    }
    sh_tree_free(&t);
}

/* NULL buffer: size query for every fixed-size success cell (122 with the size) */
TEST(sh_opt_query_null_buffer_size) {
    sh_tree t; CHECK(sh_tree_make(&t));
    if (!t.h[K_R]) { sh_tree_free(&t); return; }
    for (size_t i = 0; i < SH_QN; i++) for (int k = 0; k < K_N; k++) {
        DWORD x = sh_qtab[i].exp[k];
        if (x == NOTE_ || x == OKS || !(x & 0x40000000u)) continue;
        DWORD n = x & 0xffff, len = 0;
        SetLastError(0);
        BOOL ok = U(InternetQueryOptionA)(t.h[k], sh_qtab[i].opt, NULL, &len);
        DWORD e = GetLastError();
        CHECKF(!ok && e == ERROR_INSUFFICIENT_BUFFER && len == n, "%s on %s NULL buffer: ok=%d err %lu len %lu want 122/%lu", sh_qtab[i].name, sh_kname[k], ok, e, len, n);
        /* a too-small buffer behaves the same */
        BYTE b[8]; len = n - 1;
        SetLastError(0);
        ok = U(InternetQueryOptionA)(t.h[k], sh_qtab[i].opt, b, &len);
        e = GetLastError();
        CHECKF(!ok && e == ERROR_INSUFFICIENT_BUFFER && len == n, "%s on %s short buffer: ok=%d err %lu len %lu", sh_qtab[i].name, sh_kname[k], ok, e, len);
    }
    sh_tree_free(&t);
}

/* string cells: size query (A: chars incl NUL; W: bytes incl NUL) */
TEST(sh_opt_query_string_size_protocol) {
    sh_tree t; CHECK(sh_tree_make(&t));
    if (!t.h[K_R]) { sh_tree_free(&t); return; }
    for (size_t i = 0; i < SH_QN; i++) for (int k = 0; k < K_N; k++) {
        if (sh_qtab[i].exp[k] != OKS) continue;
        char a[1024]; DWORD al = sizeof a;
        if (!U(InternetQueryOptionA)(t.h[k], sh_qtab[i].opt, a, &al)) { CHECK(!"string option failed"); continue; }
        DWORD len = 0; SetLastError(0);
        BOOL ok = U(InternetQueryOptionA)(t.h[k], sh_qtab[i].opt, NULL, &len);
        CHECKF(!ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER && len == al + 1, "A %s on %s: size query len %lu want %lu", sh_qtab[i].name, sh_kname[k], len, al + 1);
        len = 0; SetLastError(0);
        ok = U(InternetQueryOptionW)(t.h[k], sh_qtab[i].opt, NULL, &len);
        CHECKF(!ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER && len == (al + 1) * 2, "W %s on %s: size query len %lu want %lu", sh_qtab[i].name, sh_kname[k], len, (al + 1) * 2);
    }
    sh_tree_free(&t);
}

/* values of the fixed rows that are constants */
TEST(sh_opt_query_constant_values) {
    sh_tree t; CHECK(sh_tree_make(&t));
    if (!t.h[K_R]) { sh_tree_free(&t); return; }
    for (int k = 0; k < K_N; k++) {
        DWORD v, len, e;
        if (sh_qdw(t.h[k], INTERNET_OPTION_CONNECTED_STATE, &v, &len, &e)) EXPECT_EQ(v, 1);
        if (sh_qdw(t.h[k], 82 /* AUTODIAL_MODE */, &v, &len, &e)) EXPECT_EQ(v, 1);
        if (sh_qdw(t.h[k], INTERNET_OPTION_IDLE_STATE, &v, &len, &e)) EXPECT_EQ(v, 0);
        if (sh_qdw(t.h[k], INTERNET_OPTION_OFFLINE_SEMANTICS, &v, &len, &e)) EXPECT_EQ(v, 0);
    }
    DWORD v, len, e;
    CHECK(sh_qdw(t.h[K_S], INTERNET_OPTION_HTTP_DECODING, &v, &len, &e)); EXPECT_EQ(v, 0);
    CHECK(sh_qdw(t.h[K_C], INTERNET_OPTION_HTTP_DECODING, &v, &len, &e)); EXPECT_EQ(v, 0);
    CHECK(sh_qdw(t.h[K_R], INTERNET_OPTION_HTTP_DECODING, &v, &len, &e)); EXPECT_EQ(v, 0);
    CHECK(sh_qdw(t.h[K_R], INTERNET_OPTION_SECURITY_FLAGS, &v, &len, &e)); t_note("fresh http request SECURITY_FLAGS 0x%lx", v);
    CHECK(sh_qdw(t.h[K_C], INTERNET_OPTION_READ_BUFFER_SIZE, &v, &len, &e)); t_note("connect READ_BUFFER_SIZE %lu", v);
    CHECK(sh_qdw(t.h[K_R], INTERNET_OPTION_READ_BUFFER_SIZE, &v, &len, &e)); t_note("request READ_BUFFER_SIZE %lu", v);
    CHECK(sh_qdw(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &v, &len, &e)); t_note("global MAX_CONNS_PER_SERVER %lu", v);
    CHECK(v >= 2 && v <= 128);
    CHECK(sh_qdw(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, &v, &len, &e)); CHECK(v >= 2 && v <= 128);
    for (DWORD o = 2; o <= 8; o++) { CHECK(sh_qdw(t.h[K_S], o, &v, &len, &e)); t_note("session timeout option %lu = %lu", o, v); }
    sh_tree_free(&t);
}

/* identity options: HANDLE_TYPE values, PARENT_HANDLE chain, CONTEXT_VALUE as given */
TEST(sh_opt_identity_values) {
    sh_tree t; CHECK(sh_tree_make(&t));
    if (!t.h[K_R]) { sh_tree_free(&t); return; }
    EXPECT_EQ(sh_htype(t.h[K_S], NULL), INTERNET_HANDLE_TYPE_INTERNET);
    EXPECT_EQ(sh_htype(t.h[K_C], NULL), INTERNET_HANDLE_TYPE_CONNECT_HTTP);
    EXPECT_EQ(sh_htype(t.h[K_R], NULL), INTERNET_HANDLE_TYPE_HTTP_REQUEST);
    EXPECT_EQ(sh_parent(t.h[K_S], NULL), NULL);
    EXPECT_EQ(sh_parent(t.h[K_C], NULL), t.h[K_S]);
    EXPECT_EQ(sh_parent(t.h[K_R], NULL), t.h[K_C]);
    ULONG_PTR v;
    CHECK(sh_qptr(t.h[K_C], 10, &v, NULL, NULL)); EXPECT_EQ(v, 0x11);
    CHECK(sh_qptr(t.h[K_R], 10, &v, NULL, NULL)); EXPECT_EQ(v, 0x12);
    CHECK(sh_qptr(t.h[K_R], INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); EXPECT_EQ(v, 0x12);
    char b[64]; DWORD len, e;
    CHECK(sh_qstr(t.h[K_R], INTERNET_OPTION_URL, b, sizeof b, &len, &e)); EXPECT_STR(b, "http://127.0.0.1/matrix");
    CHECK(sh_qstr(t.h[K_C], INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "mu");
    CHECK(sh_qstr(t.h[K_R], INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, "mp");
    CHECK(sh_qstr(t.h[K_S], INTERNET_OPTION_USER_AGENT, b, sizeof b, &len, &e)); EXPECT_STR(b, "matrix-agent");
    sh_tree_free(&t);
}

/* ------------------------------------------------------------------ set */
typedef struct { DWORD opt; const char *name; DWORD len; DWORD exp[K_N]; } sh_srow;
#define OK_ 0x40000000u
#define E11 ERROR_INTERNET_OPTION_NOT_SETTABLE
#define E10 ERROR_INTERNET_BAD_OPTION_LENGTH
#define E09 ERROR_INTERNET_INVALID_OPTION
static const sh_srow sh_stab[] = {
    { 1,  "CALLBACK",            8, { E18, E11, E11, E11 } },
    { 9,  "HANDLE_TYPE",         4, { E18, E11, E11, E11 } },
    { 22, "KEEP_CONNECTION",     4, { E18, E11, E11, E11 } },
    { 2,  "CONNECT_TIMEOUT len 2", 2, { E10, E10, E10, E10 } },
    { 2,  "CONNECT_TIMEOUT len 8", 8, { E10, E10, E10, E10 } },
    { 6,  "RECEIVE_TIMEOUT len 4", 4, { NOTE_, OK_, OK_, OK_ } },
    { 45, "CONTEXT_VALUE len 8", 8, { E18, OK_, OK_, OK_ } },
    { 45, "CONTEXT_VALUE len 4", 4, { NOTE_, E10, E10, E10 } },
    { 31, "SECURITY_FLAGS len 4", 4, { E18, E18, E18, OK_ } },
    { 31, "SECURITY_FLAGS len 2", 2, { E18, E18, E18, ERROR_INSUFFICIENT_BUFFER } },
    { 12, "READ_BUFFER_SIZE",     4, { NOTE_, E18, OK_, OK_ } },
    { 65, "HTTP_DECODING",        4, { E18, OK_, OK_, OK_ } },
    { 68, "CODEPAGE (1252)",      4, { NOTE_, OK_, OK_, OK_ } },
    { 0,  "option 0",             4, { E09, E09, E09, E09 } },
    { 193, "option 193",          4, { E09, E09, E09, E09 } },
    { 999, "option 999",          4, { E09, E09, E09, E09 } },
    { 16, "ASYNC_PRIORITY",       4, { NOTE_, ERROR_CALL_NOT_IMPLEMENTED, ERROR_CALL_NOT_IMPLEMENTED, ERROR_CALL_NOT_IMPLEMENTED } },
    { 21, "PARENT_HANDLE",        8, { NOTE_, NOTE_, NOTE_, NOTE_ } },
    { 23, "REQUEST_FLAGS",        4, { NOTE_, NOTE_, NOTE_, NOTE_ } },
    { 34, "URL",                  4, { NOTE_, NOTE_, NOTE_, NOTE_ } },
    { 15, "ASYNC_ID",             4, { NOTE_, NOTE_, NOTE_, NOTE_ } },
};
TEST(sh_opt_set_matrix) {
    REQUIRE(U(InternetSetOptionA));
    for (size_t i = 0; i < sizeof sh_stab / sizeof *sh_stab; i++) {
        sh_tree t; CHECK(sh_tree_make(&t));        /* fresh tree per row: no carry-over */
        for (int k = 0; k < K_N; k++) {
            const sh_srow *r = &sh_stab[i];
            if (k == K_NULL && r->exp[k] == NOTE_) continue;   /* never change process-wide state */
            BYTE buf[16]; memset(buf, 0, sizeof buf);
            if (r->opt == 6) *(DWORD *)buf = 7000;
            if (r->opt == 45) *(ULONG_PTR *)buf = 0x4242;
            if (r->opt == 12) *(DWORD *)buf = 8192;
            if (r->opt == 68) *(DWORD *)buf = 1252;
            if (r->opt == 31) *(DWORD *)buf = 0x100;
            if (r->opt == 1) *(ULONG_PTR *)buf = (ULONG_PTR)sh_cb;
            if (r->opt == 21) *(ULONG_PTR *)buf = (ULONG_PTR)t.h[K_S];
            DWORD e;
            BOOL ok = sh_set(t.h[k], r->opt, buf, r->len, &e);
            DWORD x = r->exp[k];
            if (x == NOTE_) t_note("set %s on %s: ok=%d err=%lu", r->name, sh_kname[k], ok, e);
            else if (x == OK_) CHECKF(ok, "set %s on %s: err %lu want success", r->name, sh_kname[k], e);
            else CHECKF(!ok && e == x, "set %s on %s: ok=%d err %lu want %lu", r->name, sh_kname[k], ok, e, x);
        }
        sh_tree_free(&t);
    }
}

TEST(sh_opt_set_null_buffer_or_zero_length_87) {
    sh_tree t; CHECK(sh_tree_make(&t));
    const DWORD opts[] = { 2, 6, 45, 41, 28, 12, 65, 999 };
    for (int k = K_S; k < K_N; k++) for (size_t i = 0; i < sizeof opts / sizeof *opts; i++) {
        DWORD v = 1000, e;
        BOOL ok = sh_set(t.h[k], opts[i], NULL, 4, &e);
        CHECKF(!ok && e == ERROR_INVALID_PARAMETER, "set opt %lu NULL buffer on %s: ok=%d err %lu", opts[i], sh_kname[k], ok, e);
        ok = sh_set(t.h[k], opts[i], &v, 0, &e);
        CHECKF(!ok && e == ERROR_INVALID_PARAMETER, "set opt %lu len 0 on %s: ok=%d err %lu", opts[i], sh_kname[k], ok, e);
    }
    sh_tree_free(&t);
}

TEST(sh_opt_set_bad_handles) {
    DWORD v = 1000, e;
    CHECK(!sh_set(SH_GARBAGE1, INTERNET_OPTION_SEND_TIMEOUT, &v, 4, &e)); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    CHECK(!sh_set(SH_GARBAGE2, INTERNET_OPTION_CONTEXT_VALUE, &v, 4, &e)); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    CHECK(!sh_qdw(SH_GARBAGE1, INTERNET_OPTION_HANDLE_TYPE, &v, NULL, &e)); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    DWORD len = 77;
    SetLastError(0);
    CHECK(!U(InternetQueryOptionA)(SH_GARBAGE2, INTERNET_OPTION_HANDLE_TYPE, &v, &len));
    EXPECT_ERR(ERROR_INVALID_HANDLE); EXPECT_EQ(len, 0);
    /* NULL handle + per-handle option */
    CHECK(!sh_set(NULL, INTERNET_OPTION_CONTEXT_VALUE, &v, 8, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    CHECK(!sh_setdw(NULL, INTERNET_OPTION_HTTP_DECODING, 1, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    char ua[] = "x";
    CHECK(!sh_set(NULL, INTERNET_OPTION_USER_AGENT, ua, 1, &e)); t_note("set USER_AGENT on NULL: err %lu", e);
}

TEST(sh_opt_user_agent_wrong_handle_12018) {
    sh_tree t; CHECK(sh_tree_make(&t));
    char ua[] = "nope"; DWORD e;
    for (int k = K_C; k < K_N; k++) {
        if (!t.h[k]) continue;
        CHECK(!sh_set(t.h[k], INTERNET_OPTION_USER_AGENT, ua, sizeof ua, &e)); EXPECT_EQ(e, E18);
        /* "" is rejected with 12010 before the handle type is looked at */
        char empty[] = "";
        CHECK(!sh_set(t.h[k], INTERNET_OPTION_USER_AGENT, empty, 1, &e)); EXPECT_EQ(e, E10);
    }
    sh_tree_free(&t);
}

/* timeouts are per handle; a child copies the parent's value when it is created */
TEST(sh_opt_timeouts_per_handle_and_inherited) {
    HINTERNET s = sh_open("to"); CHECK(s != NULL); if (!s) return;
    DWORD e, v;
    CHECK(sh_setdw(s, INTERNET_OPTION_RECEIVE_TIMEOUT, 4321, &e));
    CHECK(sh_qdw(s, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 4321);
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    if (c) { CHECK(sh_qdw(c, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 4321); }
    if (c) CHECK(sh_setdw(c, INTERNET_OPTION_RECEIVE_TIMEOUT, 2222, &e));
    CHECK(sh_qdw(s, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 4321);
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL;
    if (r) { CHECK(sh_qdw(r, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 2222); }
    if (r) { CHECK(sh_setdw(r, INTERNET_OPTION_RECEIVE_TIMEOUT, 1111, &e)); CHECK(sh_qdw(r, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 1111); }
    if (c) { CHECK(sh_qdw(c, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 2222); }
    /* setting the session afterwards does not reach existing children */
    CHECK(sh_setdw(s, INTERNET_OPTION_RECEIVE_TIMEOUT, 9999, &e));
    if (c) { CHECK(sh_qdw(c, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 2222); }
    /* all seven timeout options round-trip on the session */
    for (DWORD o = 2; o <= 8; o++) {
        if (o == 3 || o == 4) continue;   /* RETRIES / BACKOFF: not timeouts */
        CHECK(sh_setdw(s, o, 3000 + o, &e));
        CHECK(sh_qdw(s, o, &v, NULL, &e)); CHECKF(v == 3000 + o, "timeout option %lu read %lu", o, v);
    }
    if (r) sh_close(r);
    if (c) sh_close(c);
    sh_close(s);
}

TEST(sh_opt_http_decoding_roundtrip) {
    sh_tree t; CHECK(sh_tree_make(&t));
    for (int k = K_S; k < K_N; k++) {
        DWORD e, v;
        if (!t.h[k]) continue;
        CHECK(sh_setdw(t.h[k], INTERNET_OPTION_HTTP_DECODING, 1, &e));
        CHECK(sh_qdw(t.h[k], INTERNET_OPTION_HTTP_DECODING, &v, NULL, &e)); EXPECT_EQ(v, 1);
        CHECK(sh_setdw(t.h[k], INTERNET_OPTION_HTTP_DECODING, 0, &e));
        CHECK(sh_qdw(t.h[k], INTERNET_OPTION_HTTP_DECODING, &v, NULL, &e)); EXPECT_EQ(v, 0);
    }
    sh_tree_free(&t);
}

TEST(sh_opt_security_flags_request_only_adds) {
    sh_tree t; CHECK(sh_tree_make(&t));
    if (!t.h[K_R]) { sh_tree_free(&t); return; }
    DWORD v0, v, e;
    CHECK(sh_qdw(t.h[K_R], INTERNET_OPTION_SECURITY_FLAGS, &v0, NULL, &e));
    CHECK(sh_setdw(t.h[K_R], INTERNET_OPTION_SECURITY_FLAGS, SECURITY_FLAG_IGNORE_UNKNOWN_CA, &e));
    CHECK(sh_qdw(t.h[K_R], INTERNET_OPTION_SECURITY_FLAGS, &v, NULL, &e));
    t_note("SECURITY_FLAGS on http request before %lx after set 0x100: %lx", v0, v);
    sh_tree_free(&t);
}

/* ------------------------------------------------------------------ FTP handle kinds */
typedef struct { DWORD opt; const char *name; DWORD exp[3]; } sh_frow;   /* FCon, FFnd, FFil */
static const sh_frow sh_ftab[] = {
    { 9,  "HANDLE_TYPE",       { OKN(4), OKN(4), OKN(4) } },
    { 21, "PARENT_HANDLE",     { OKN(8), OKN(8), OKN(8) } },
    { 45, "CONTEXT_VALUE",     { OKN(8), OKN(8), OKN(8) } },
    { 12, "READ_BUFFER_SIZE",  { OKN(4), OKN(4), OKN(4) } },
    { 22, "KEEP_CONNECTION",   { E18, E18, E18 } },
    { 23, "REQUEST_FLAGS",     { E18, OKN(4), OKN(4) } },
    { 28, "USERNAME",          { OKS, OKS, OKS } },
    { 34, "URL",               { E18, OKS, OKS } },
    { 41, "USER_AGENT",        { E18, E18, E18 } },
    { 65, "HTTP_DECODING",     { E18, E18, E18 } },
    { 68, "CODEPAGE",          { OKN(4), OKN(4), OKN(4) } },
    { 31, "SECURITY_FLAGS",    { E18, E18, E18 } },
    { 38, "PROXY",             { E18, E18, E18 } },
    { 58, "REQUEST_PRIORITY",  { E18, E18, E18 } },
    { 53, "SECONDARY_CACHE_KEY", { E18, E18, E18 } },
};
TEST(sh_opt_ftp_handle_matrix) {
    REQUIRE(U(FtpFindFirstFileA)); REQUIRE(U(FtpOpenFileA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftpm");
    HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 1) : NULL;
    CHECK(c != NULL);
    if (c) {
        WIN32_FIND_DATAA fd;
        HINTERNET fh = U(FtpFindFirstFileA)(c, "*", &fd, INTERNET_FLAG_RELOAD, 2);
        CHECK(fh != NULL);
        for (int pass = 0; pass < 2; pass++) {
            HINTERNET hs[3] = { c, NULL, NULL };
            const char *names[3] = { "FCon", "FFnd", "FFil" };
            if (pass == 0) hs[1] = fh;
            else hs[2] = U(FtpOpenFileA)(c, "hello.txt", GENERIC_READ, FTP_TRANSFER_TYPE_BINARY | INTERNET_FLAG_RELOAD, 3);
            if (pass == 1) CHECKF(hs[2] != NULL, "FtpOpenFile err %lu", GetLastError());
            for (size_t i = 0; i < sizeof sh_ftab / sizeof *sh_ftab; i++) for (int k = 0; k < 3; k++) {
                if (!hs[k] || (pass == 1 && k == 0)) continue;
                BYTE buf[1024]; memset(buf, 0, sizeof buf); DWORD len = sizeof buf;
                SetLastError(0xdeadbeef);
                BOOL ok = U(InternetQueryOptionA)(hs[k], sh_ftab[i].opt, buf, &len);
                DWORD e = GetLastError(), x = sh_ftab[i].exp[k];
                if (x == OKS) CHECKF(ok, "%s on %s: err %lu", sh_ftab[i].name, names[k], e);
                else if (x & 0x40000000u) CHECKF(ok && len == (x & 0xffff), "%s on %s: ok=%d err %lu len %lu", sh_ftab[i].name, names[k], ok, ok ? 0 : e, len);
                else CHECKF(!ok && e == x, "%s on %s: ok=%d err %lu want %lu", sh_ftab[i].name, names[k], ok, ok ? 0 : e, x);
            }
            if (pass == 0 && fh) { EXPECT_EQ(sh_htype(fh, NULL), 5); sh_close(fh); fh = NULL; }
            if (pass == 1 && hs[2]) { EXPECT_EQ(sh_htype(hs[2], NULL), 7); char b[16]; t_inet_read_all(hs[2], b, sizeof b, NULL); sh_close(hs[2]); }
        }
        sh_close(c);
    }
    if (s) sh_close(s);
    srv_stop(f);
}
