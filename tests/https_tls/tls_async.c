/* tls_async.c - HTTPS in asynchronous mode (INTERNET_FLAG_ASYNC): certificate errors and TLS failures are
 * reported through INTERNET_STATUS_REQUEST_COMPLETE (INTERNET_ASYNC_RESULT.dwError), the retry protocol works
 * the same way, and the status callback sequence of a secure request. Servers: shared schannel server, the raw
 * ClientHello observer (tls_util.c). Every wait is bounded (8 s). Callback records are static (callbacks for
 * HANDLE_CLOSING can arrive after a test returns). */
#include "tls_util.h"

#define AREC_MAX 512
typedef struct {
    volatile LONG n;
    DWORD st[AREC_MAX];
    DWORD_PTR res[AREC_MAX]; DWORD err[AREC_MAX];
    HANDLE done;           /* REQUEST_COMPLETE */
    HANDLE closing;        /* HANDLE_CLOSING */
} arec;

static void CALLBACK acb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD len) {
    arec *r = (arec *)ctx;
    if (!r) return;
    LONG i = InterlockedIncrement(&r->n) - 1;
    if (i < AREC_MAX) {
        r->st[i] = status;
        if (status == INTERNET_STATUS_REQUEST_COMPLETE && info && len >= sizeof(INTERNET_ASYNC_RESULT)) {
            INTERNET_ASYNC_RESULT *a = info; r->res[i] = a->dwResult; r->err[i] = a->dwError;
        }
    }
    if (status == INTERNET_STATUS_REQUEST_COMPLETE) SetEvent(r->done);
    if (status == INTERNET_STATUS_HANDLE_CLOSING) SetEvent(r->closing);
}
static void arec_reset(arec *r) {
    if (!r->done) { r->done = CreateEventW(NULL, FALSE, FALSE, NULL); r->closing = CreateEventW(NULL, FALSE, FALSE, NULL); }
    ResetEvent(r->done); ResetEvent(r->closing);
    r->n = 0; memset(r->st, 0, sizeof r->st);
}
static int arec_count(arec *r, DWORD status) {
    int k = 0; LONG n = r->n < AREC_MAX ? r->n : AREC_MAX;
    for (LONG i = 0; i < n; i++) if (r->st[i] == status) k++;
    return k;
}
static int arec_first(arec *r, DWORD status, int from) {
    LONG n = r->n < AREC_MAX ? r->n : AREC_MAX;
    for (LONG i = from; i < n; i++) if (r->st[i] == status) return (int)i;
    return -1;
}
static int arec_last(arec *r, DWORD status) {
    LONG n = r->n < AREC_MAX ? r->n : AREC_MAX;
    for (LONG i = n - 1; i >= 0; i--) if (r->st[i] == status) return (int)i;
    return -1;
}
static void arec_dump(arec *r, const char *tag) {
    char b[1024]; size_t o = 0; LONG n = r->n < AREC_MAX ? r->n : AREC_MAX;
    for (LONG i = 0; i < n && o < sizeof b - 16; i++) o += snprintf(b + o, sizeof b - o, "%lu ", r->st[i]);
    b[o] = 0; t_note("%s: statuses %s", tag, b);
}

typedef struct { HINTERNET hi, hc, hr; } areq;
static int areq_open(areq *q, arec *r, const char *host, unsigned short port, DWORD flags) {
    memset(q, 0, sizeof *q);
    q->hi = t_inet_open_ex("tls-async", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_ASYNC, 5000);
    if (!q->hi) return 0;
    U(InternetSetStatusCallbackA)(q->hi, acb);
    q->hc = U(InternetConnectA)(q->hi, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)r);
    if (!q->hc) return 0;
    q->hr = U(HttpOpenRequestA)(q->hc, "GET", "/a", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE | flags, (DWORD_PTR)r);
    return q->hr != NULL;
}
static void areq_close(areq *q, arec *r) {
    if (q->hr) { U(InternetCloseHandle)(q->hr); WaitForSingleObject(r->closing, 2000); }
    if (q->hc) U(InternetCloseHandle)(q->hc);
    if (q->hi) U(InternetCloseHandle)(q->hi);
    memset(q, 0, sizeof *q);
}
/* async send: returns 0 / error; *pend = 1 if the call returned ERROR_IO_PENDING. *res = dwResult of the completion. */
static DWORD async_send(areq *q, arec *r, int *pend, DWORD_PTR *res) {
    ResetEvent(r->done);
    int from = r->n;
    SetLastError(0xDEAD);
    BOOL ok = U(HttpSendRequestA)(q->hr, NULL, 0, NULL, 0);
    DWORD e = ok ? 0 : GetLastError();
    if (pend) *pend = (!ok && e == ERROR_IO_PENDING);
    if (res) *res = ok;
    if (ok || e != ERROR_IO_PENDING) return e;
    if (WaitForSingleObject(r->done, 8000) != WAIT_OBJECT_0) return 0xDEAD0001;
    int i = arec_first(r, INTERNET_STATUS_REQUEST_COMPLETE, from);
    if (i < 0) return 0xDEAD0002;
    if (res) *res = r->res[i];
    return r->res[i] ? 0 : r->err[i];
}
static size_t async_read_all(areq *q, arec *r, char *buf, size_t cap) {
    size_t tot = 0;
    for (int guard = 0; guard < 256; guard++) {
        DWORD got = 0;
        ResetEvent(r->done);
        BOOL ok = U(InternetReadFile)(q->hr, buf + tot, (DWORD)(cap - 1 - tot), &got);
        if (!ok) {
            if (GetLastError() != ERROR_IO_PENDING) break;
            if (WaitForSingleObject(r->done, 8000) != WAIT_OBJECT_0) break;
            continue;   /* data now buffered: the next call returns it */
        }
        if (got == 0) break;
        tot += got;
        if (tot >= cap - 1) break;
    }
    buf[tot] = 0;
    return tot;
}
#define ASKIP(s) do { if (!(s)) { TLS_SKIP_SRV(); } } while (0)
/* success-path async send: one retry on a transient abort/reset of a fresh loopback TLS connection (seen about once
 * per boot on the VM in several areas), noted */
static DWORD async_send_ok(areq *q, arec *r, int *pend, DWORD_PTR *res) {
    DWORD e = async_send(q, r, pend, res);
    if (e == ERROR_INTERNET_CONNECTION_RESET) { t_note("transient %lu on async send, retrying once", e); e = async_send(q, r, pend, res); }
    return e;
}

/* ------------------------------------------------------------------ certificate errors through the completion */
TEST(tls_async_unknown_ca_completion) {
    REQUIRE(U(InternetSetStatusCallbackA));
    static arec r; arec_reset(&r);
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); ASKIP(s);
    areq q;
    if (!areq_open(&q, &r, "127.0.0.1", srv_port(s), 0)) { areq_close(&q, &r); srv_stop(s); t_skip("async open failed"); return; }
    int pend; DWORD_PTR res;
    DWORD e = async_send(&q, &r, &pend, &res);
    EXPECT_EQ(pend, 1);
    EXPECT_EQ(e, ERROR_INTERNET_INVALID_CA);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(arec_count(&r, INTERNET_STATUS_REQUEST_COMPLETE), 1);
    EXPECT_EQ(tls_secflags(q.hr), 0);
    EXPECT_EQ(srv_req_count(s), 0);
    arec_dump(&r, "unknown CA");
    areq_close(&q, &r);
    srv_stop(s);
}

TEST(tls_async_retry_with_flag_then_read) {
    REQUIRE(U(InternetSetStatusCallbackA));
    static arec r; arec_reset(&r);
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); ASKIP(s);
    areq q;
    if (!areq_open(&q, &r, "127.0.0.1", srv_port(s), 0)) { areq_close(&q, &r); srv_stop(s); t_skip("async open failed"); return; }
    int pend; DWORD_PTR res;
    DWORD e = async_send(&q, &r, &pend, &res);
    EXPECT_EQ(e, ERROR_INTERNET_INVALID_CA);
    CHECK(t_https_secflags(q.hr, 0x100));
    e = async_send_ok(&q, &r, &pend, &res);
    EXPECT_EQ(e, 0);
    EXPECT_EQ(pend, 1);
    EXPECT_EQ(res, 1);
    DWORD stc = 0, l = sizeof stc;
    CHECK(U(HttpQueryInfoA)(q.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &stc, &l, NULL));
    EXPECT_EQ(stc, 200);
    char b[256]; size_t n = async_read_all(&q, &r, b, sizeof b);
    EXPECT_EQ(n, 5);
    EXPECT_STR(b, "hello");
    DWORD f = tls_secflags(q.hr);
    EXPECT_EQ(f & 0x100, 0x100);
    EXPECT_EQ(f & SECURITY_FLAG_SECURE, SECURITY_FLAG_SECURE);
    EXPECT_EQ(srv_req_count(s), 1);
    areq_close(&q, &r);
    srv_stop(s);
}

TEST(tls_async_success_status_order) {
    REQUIRE(U(InternetSetStatusCallbackA));
    static arec r; arec_reset(&r);
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); ASKIP(s);
    areq q;
    if (!areq_open(&q, &r, "127.0.0.1", srv_port(s), 0)) { areq_close(&q, &r); srv_stop(s); t_skip("async open failed"); return; }
    t_https_secflags(q.hr, 0x100);
    arec_reset(&r);
    int pend; DWORD_PTR res;
    DWORD e = async_send_ok(&q, &r, &pend, &res);
    EXPECT_EQ(e, 0);
    arec_dump(&r, "success");
    int con = arec_first(&r, INTERNET_STATUS_CONNECTING_TO_SERVER, 0), cod = arec_first(&r, INTERNET_STATUS_CONNECTED_TO_SERVER, 0);
    int snd = arec_first(&r, INTERNET_STATUS_SENDING_REQUEST, 0), sent = arec_first(&r, INTERNET_STATUS_REQUEST_SENT, 0);
    int rcv = arec_first(&r, INTERNET_STATUS_RECEIVING_RESPONSE, 0), rcvd = arec_first(&r, INTERNET_STATUS_RESPONSE_RECEIVED, 0);
    int done = arec_first(&r, INTERNET_STATUS_REQUEST_COMPLETE, 0);
    CHECK(con >= 0 && cod > con);
    CHECK(snd >= 0 && sent > snd);
    CHECK(cod < sent);
    CHECK(rcv > sent && rcvd > rcv);
    CHECK(done > rcvd);
    EXPECT_EQ(done, arec_last(&r, INTERNET_STATUS_REQUEST_COMPLETE));
    EXPECT_EQ(arec_count(&r, INTERNET_STATUS_CONNECTED_TO_SERVER), 1);
    areq_close(&q, &r);
    srv_stop(s);
}

TEST(tls_async_cert_error_status_sequence) {
    REQUIRE(U(InternetSetStatusCallbackA));
    static arec r; arec_reset(&r);
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); ASKIP(s);
    areq q;
    if (!areq_open(&q, &r, "127.0.0.1", srv_port(s), 0)) { areq_close(&q, &r); srv_stop(s); t_skip("async open failed"); return; }
    arec_reset(&r);
    int pend; DWORD_PTR res;
    DWORD e = async_send(&q, &r, &pend, &res);
    EXPECT_EQ(e, ERROR_INTERNET_INVALID_CA);
    arec_dump(&r, "12045");
    CHECK(arec_first(&r, INTERNET_STATUS_CONNECTED_TO_SERVER, 0) >= 0);
    EXPECT_EQ(arec_count(&r, INTERNET_STATUS_RECEIVING_RESPONSE), 0);
    EXPECT_EQ(arec_count(&r, INTERNET_STATUS_RESPONSE_RECEIVED), 0);
    EXPECT_EQ(arec_last(&r, INTERNET_STATUS_REQUEST_COMPLETE), (int)r.n - 1);
    /* Win10: 80 20 21 50 51 100 (DETECTING_PROXY, CONNECTING, CONNECTED, CLOSING_CONNECTION, CONNECTION_CLOSED, COMPLETE) */
    EXPECT_EQ(arec_count(&r, INTERNET_STATUS_SENDING_REQUEST), 0);
    EXPECT_EQ(arec_count(&r, INTERNET_STATUS_REQUEST_SENT), 0);
    EXPECT_EQ(arec_count(&r, INTERNET_STATUS_CLOSING_CONNECTION), 1);
    EXPECT_EQ(arec_count(&r, INTERNET_STATUS_CONNECTION_CLOSED), 1);
    t_note("12045: SENDING_REQUEST=%d REQUEST_SENT=%d CLOSING_CONNECTION=%d CONNECTION_CLOSED=%d", arec_count(&r, INTERNET_STATUS_SENDING_REQUEST),
           arec_count(&r, INTERNET_STATUS_REQUEST_SENT), arec_count(&r, INTERNET_STATUS_CLOSING_CONNECTION), arec_count(&r, INTERNET_STATUS_CONNECTION_CLOSED));
    areq_close(&q, &r);
    srv_stop(s);
}

typedef struct { int profile; DWORD sec; DWORD want; const char *name; } arow;
TEST(tls_async_cert_error_matrix) {
    REQUIRE(U(InternetSetStatusCallbackA));
    static const arow rows[] = {
        { SRV_CERT_CN_OTHER, 0x100, ERROR_INTERNET_SEC_CERT_CN_INVALID, "CN_OTHER" },
        { SRV_CERT_CN_OTHER, 0x1100, 0, "CN_OTHER+ignore" },
        { SRV_CERT_EXPIRED, 0x100, ERROR_INTERNET_SEC_CERT_DATE_INVALID, "EXPIRED" },
        { SRV_CERT_EXPIRED, 0x2100, 0, "EXPIRED+ignore" },
        { SRV_CERT_CLIENT, 0x100, ERROR_INTERNET_SEC_INVALID_CERT, "CLIENT EKU" },
        { SRV_CERT_CLIENT, 0x1300, 0, "CLIENT EKU+ignore" },
        { SRV_CERT_NO_EKU, 0x100, 0, "NO_EKU" },
    };
    static arec r;
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        arec_reset(&r);
        srv *s = tls_srv(rows[i].profile, NULL, 0); ASKIP(s);
        areq q;
        if (!areq_open(&q, &r, "127.0.0.1", srv_port(s), 0)) { areq_close(&q, &r); srv_stop(s); t_skip("async open failed"); return; }
        t_https_secflags(q.hr, rows[i].sec);
        int pend; DWORD_PTR res;
        DWORD e = rows[i].want ? async_send(&q, &r, &pend, &res) : async_send_ok(&q, &r, &pend, &res);
        CHECKF(e == rows[i].want, "%s sec=0x%lx: %lu want %lu", rows[i].name, rows[i].sec, e, rows[i].want);
        CHECKF(pend == 1, "%s: not pending", rows[i].name);
        if (!rows[i].want) { char b[64]; size_t n = async_read_all(&q, &r, b, sizeof b); CHECKF(n == 5, "%s body %zu", rows[i].name, n); }
        areq_close(&q, &r);
        srv_stop(s);
    }
}

TEST(tls_async_client_cert_needed) {
    REQUIRE(U(InternetSetStatusCallbackA));
    static arec r; arec_reset(&r);
    int rc; srv *s = tls_srv_cfg(SRV_CERT_LOCALHOST, 0, 1, NULL, 0, &rc);
    if (!s) { t_skip("HTTPS server unavailable: %s", srv_strerror(rc)); return; }
    areq q;
    if (!areq_open(&q, &r, "127.0.0.1", srv_port(s), 0)) { areq_close(&q, &r); srv_stop(s); t_skip("async open failed"); return; }
    t_https_secflags(q.hr, SECURITY_SET_MASK);
    int pend; DWORD_PTR res;
    DWORD e = async_send(&q, &r, &pend, &res);
    EXPECT_EQ(e, ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED);
    EXPECT_EQ(pend, 1);
    /* continue without a certificate (index -1), resend */
    DWORD idx = (DWORD)-1;
    CHECK(U(InternetSetOptionA)(q.hr, INTERNET_OPTION_SECURITY_SELECT_CLIENT_CERT, &idx, sizeof idx));
    e = async_send_ok(&q, &r, &pend, &res);
    EXPECT_EQ(e, 0);
    areq_close(&q, &r);
    srv_stop(s);
}

static void async_broken(int reaction, DWORD want, const char *name) {
    static arec r; arec_reset(&r);
    th_srv *t = th_start(reaction);
    if (!t) { t_skip("winsock unavailable"); return; }
    areq q;
    if (!areq_open(&q, &r, "127.0.0.1", th_port(t), 0)) { areq_close(&q, &r); th_stop(t); t_skip("async open failed"); return; }
    int pend; DWORD_PTR res;
    DWORD e = async_send(&q, &r, &pend, &res);
    CHECKF(e == want, "%s: %lu %s want %lu", name, e, t_inet_errname(e), want);
    EXPECT_EQ(res, 0);
    areq_close(&q, &r);
    th_stop(t);
}
TEST(tls_async_broken_alert) { REQUIRE(U(InternetSetStatusCallbackA)); async_broken(TH_ALERT, ERROR_INTERNET_SECURITY_CHANNEL_ERROR, "alert"); }
TEST(tls_async_broken_garbage) { REQUIRE(U(InternetSetStatusCallbackA)); async_broken(TH_GARBAGE, ERROR_INTERNET_SECURITY_CHANNEL_ERROR, "garbage"); }
TEST(tls_async_broken_plaintext) { REQUIRE(U(InternetSetStatusCallbackA)); async_broken(TH_PLAINTEXT_HTTP, ERROR_INTERNET_SECURITY_CHANNEL_ERROR, "plaintext"); }
TEST(tls_async_broken_reset) { REQUIRE(U(InternetSetStatusCallbackA)); async_broken(TH_RESET, ERROR_INTERNET_CONNECTION_RESET, "reset"); }

TEST(tls_async_info_options_after_completion) {
    REQUIRE(U(InternetSetStatusCallbackA));
    static arec r; arec_reset(&r);
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); ASKIP(s);
    areq q;
    if (!areq_open(&q, &r, "127.0.0.1", srv_port(s), 0)) { areq_close(&q, &r); srv_stop(s); t_skip("async open failed"); return; }
    t_https_secflags(q.hr, 0x100);
    int pend; DWORD_PTR res;
    { DWORD e0 = async_send_ok(&q, &r, &pend, &res); EXPECT_EQ(e0, 0); }
    tls_sec_conn_info ci; memset(&ci, 0, sizeof ci); ci.dwSize = sizeof ci; DWORD l = sizeof ci;
    CHECK(U(InternetQueryOptionA)(q.hr, INTERNET_OPTION_SECURITY_CONNECTION_INFO, &ci, &l));
    EXPECT_EQ(ci.fSecure, 1);
    CHECK(ci.connectionInfo.dwProtocol != 0);
    DWORD kb = 0; l = sizeof kb;
    CHECK(U(InternetQueryOptionA)(q.hr, INTERNET_OPTION_SECURITY_KEY_BITNESS, &kb, &l));
    EXPECT_EQ(kb, ci.connectionInfo.dwCipherStrength);
    PCCERT_CHAIN_CONTEXT ch = NULL; l = sizeof ch;
    CHECK(U(InternetQueryOptionA)(q.hr, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &ch, &l) && ch);
    if (ch) U(CertFreeCertificateChain)(ch);
    char b[64]; async_read_all(&q, &r, b, sizeof b);
    areq_close(&q, &r);
    srv_stop(s);
}

TEST(tls_async_openurl_unknown_ca) {
    REQUIRE(U(InternetOpenUrlA));
    static arec r; arec_reset(&r);
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); ASKIP(s);
    HINTERNET hi = t_inet_open_ex("tls-async", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_ASYNC, 5000);
    if (!hi) { srv_stop(s); t_skip("session"); return; }
    U(InternetSetStatusCallbackA)(hi, acb);
    char url[128]; snprintf(url, sizeof url, "https://127.0.0.1:%u/u", srv_port(s));
    SetLastError(0xDEAD);
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, T_INET_FRESH, (DWORD_PTR)&r);
    DWORD e = GetLastError();
    EXPECT_EQ(h, NULL);
    EXPECT_EQ(e, ERROR_IO_PENDING);
    if (!h && e == ERROR_IO_PENDING) {
        DWORD w_ = WaitForSingleObject(r.done, 8000); EXPECT_EQ(w_, WAIT_OBJECT_0);
        int i = arec_first(&r, INTERNET_STATUS_REQUEST_COMPLETE, 0);
        CHECK(i >= 0);
        if (i >= 0) {
            EXPECT_EQ(r.err[i], ERROR_INTERNET_INVALID_CA);
            t_note("OpenUrl completion dwResult=0x%llx", (unsigned long long)r.res[i]);
            if (r.res[i]) U(InternetCloseHandle)((HINTERNET)r.res[i]);
        }
        CHECK(arec_count(&r, INTERNET_STATUS_HANDLE_CREATED) >= 1);
    }
    if (h) U(InternetCloseHandle)(h);
    U(InternetCloseHandle)(hi);
    EXPECT_EQ(srv_req_count(s), 0);
    srv_stop(s);
}

TEST(tls_async_sendrequestex_unknown_ca) {
    REQUIRE(U(HttpSendRequestExA));
    static arec r; arec_reset(&r);
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "posted"), S_END() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 4); ASKIP(s);
    areq q;
    if (!areq_open(&q, &r, "127.0.0.1", srv_port(s), 0)) { areq_close(&q, &r); srv_stop(s); t_skip("async open failed"); return; }
    INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.dwBufferTotal = 4;
    ResetEvent(r.done);
    SetLastError(0xDEAD);
    BOOL ok = U(HttpSendRequestExA)(q.hr, &ib, NULL, 0, (DWORD_PTR)&r);
    DWORD e = ok ? 0 : GetLastError();
    if (!ok && e == ERROR_IO_PENDING) {
        DWORD w_ = WaitForSingleObject(r.done, 8000); EXPECT_EQ(w_, WAIT_OBJECT_0);
        int i = arec_last(&r, INTERNET_STATUS_REQUEST_COMPLETE);
        e = i >= 0 ? (r.res[i] ? 0 : r.err[i]) : 0xDEAD0002;
    }
    EXPECT_EQ(e, ERROR_INTERNET_INVALID_CA);
    EXPECT_EQ(srv_req_count(s), 0);
    areq_close(&q, &r);
    srv_stop(s);
}

TEST(tls_async_ignore_flags_at_open) {
    REQUIRE(U(InternetSetStatusCallbackA));
    /* the request flags INTERNET_FLAG_IGNORE_CERT_* apply in async mode as well (CN_OTHER, 0x100 added) */
    static arec r; arec_reset(&r);
    srv *s = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); ASKIP(s);
    areq q;
    if (!areq_open(&q, &r, "127.0.0.1", srv_port(s), INTERNET_FLAG_IGNORE_CERT_CN_INVALID)) { areq_close(&q, &r); srv_stop(s); t_skip("async open failed"); return; }
    t_https_secflags(q.hr, 0x100);
    int pend; DWORD_PTR res;
    { DWORD e0 = async_send_ok(&q, &r, &pend, &res); EXPECT_EQ(e0, 0); }
    char b[64]; size_t bn = async_read_all(&q, &r, b, sizeof b); EXPECT_EQ(bn, 5);
    areq_close(&q, &r);
    srv_stop(s);
}

/* ERROR_MASK COMBINED_SEC_CERT in async mode: 12055 arrives as REQUEST_COMPLETE dwError, the read-back flags name the
 * errors (DLG_FLAGS_INVALID_CA | DLG_FLAGS_SEC_CERT_CN_INVALID), and the retry with both ignore bits completes */
TEST(tls_async_combined_cert_errors) {
    REQUIRE(U(InternetSetStatusCallbackA));
    static arec r; arec_reset(&r);
    srv *s = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); ASKIP(s);
    areq q;
    if (!areq_open(&q, &r, "127.0.0.1", srv_port(s), 0)) { areq_close(&q, &r); srv_stop(s); t_skip("async open failed"); return; }
    DWORD m = INTERNET_ERROR_MASK_COMBINED_SEC_CERT;
    CHECK(U(InternetSetOptionA)(q.hr, INTERNET_OPTION_ERROR_MASK, &m, sizeof m));
    int pend; DWORD_PTR res;
    DWORD e = async_send(&q, &r, &pend, &res);
    EXPECT_EQ(pend, 1);
    EXPECT_EQ(e, ERROR_INTERNET_SEC_CERT_ERRORS);
    EXPECT_EQ(res, 0);
    DWORD f = tls_secflags(q.hr);
    t_note("async combined: flags=0x%lx", f);
    EXPECT_EQ(f & 0x07A00000, 0x03000000);
    t_https_secflags(q.hr, 0x1100);
    e = async_send_ok(&q, &r, &pend, &res);
    EXPECT_EQ(e, 0);
    EXPECT_EQ(res, 1);
    char b[64]; size_t n = async_read_all(&q, &r, b, sizeof b);
    EXPECT_EQ(n, 5);
    EXPECT_EQ(srv_req_count(s), 1);
    areq_close(&q, &r);
    srv_stop(s);
}
