/* http_auth: authentication through HttpSendRequestEx + InternetWriteFile + HttpEndRequest.
 *
 * Decomp (Win10 wininet): HttpEndRequestA/W -> HttpWrapSendRequest(..., AR_TYPE 0x12); HttpSendRequestExA/W use
 * AR_TYPE 0x11 and HttpSendRequestA/W loop internally. In HTTP_REQUEST_HANDLE_OBJECT::HttpSendRequest_Start the
 * auth state 0x2f00 (ERROR_INTERNET_FORCE_RETRY, set when credentials are available for a 401/407) is handed back
 * to the caller only when AR_TYPE == 0x12 and INTERNET_FLAG_NO_AUTH (0x4f4 & 0x40000) is clear: the application
 * has to send the request (and its body) again. Without credentials the 401 is a normal completion. */
#include "auth.h"

#define CH_BASIC_X "WWW-Authenticate: Basic realm=\"i7ex\"\r\n"
#define CH_PBASIC_X "Proxy-Authenticate: Basic realm=\"i7exproxy\"\r\n"
#define X_NONCE "e7a1f3b6c9d24e58a0b1c2d3e4f50617"
#define CH_DIGEST_X "WWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", nonce=\"" X_NONCE "\", opaque=\"0badc0de\"\r\n"

typedef struct {
    BOOL ex_ok, end_ok; DWORD ex_err, end_err, status, written;
} xround;

/* One HttpSendRequestEx/InternetWriteFile/HttpEndRequest round on hr. */
static void x_round(HINTERNET hr, const char *body, xround *x, int wide) {
    memset(x, 0, sizeof *x);
    DWORD bl = body ? (DWORD)strlen(body) : 0;
    SetLastError(0xdeadbeef);
    if (wide) {
        INTERNET_BUFFERSW b; memset(&b, 0, sizeof b); b.dwStructSize = sizeof b; b.dwBufferTotal = bl;
        x->ex_ok = U(HttpSendRequestExW)(hr, &b, NULL, 0, 0);
    } else {
        INTERNET_BUFFERSA b; memset(&b, 0, sizeof b); b.dwStructSize = sizeof b; b.dwBufferTotal = bl;
        x->ex_ok = U(HttpSendRequestExA)(hr, &b, NULL, 0, 0);
    }
    x->ex_err = x->ex_ok ? 0 : GetLastError();
    if (!x->ex_ok) return;
    if (bl) { DWORD w = 0; if (U(InternetWriteFile)(hr, body, bl, &w)) x->written = w; }
    SetLastError(0xdeadbeef);
    x->end_ok = wide ? U(HttpEndRequestW)(hr, NULL, 0, 0) : U(HttpEndRequestA)(hr, NULL, 0, 0);
    x->end_err = x->end_ok ? 0 : GetLastError();
    x->status = a_status(hr);
}

/* Rounds until HttpEndRequest does not ask for a retry (max 4). Returns the number of rounds. */
static int x_loop(HINTERNET hr, const char *body, xround *last, int wide, int *force_retries) {
    int n = 0; *force_retries = 0;
    for (; n < 4; ) {
        x_round(hr, body, last, wide); n++;
        if (last->ex_ok && !last->end_ok && last->end_err == ERROR_INTERNET_FORCE_RETRY) { (*force_retries)++; continue; }
        break;
    }
    return n;
}

static HINTERNET x_open(HINTERNET hc, const char *verb, const char *path, DWORD flags) {
    return U(HttpOpenRequestA)(hc, verb, path, NULL, NULL, NULL, flags ? flags : T_INET_FRESH, 0);
}

TEST(auth_ex_basic_connect_creds_force_retry) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.challenge = CH_BASIC_X; g.accept[0] = a_basic("exu", "exp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "exu", "exp");
    HINTERNET hr = x_open(hc, "POST", "/ex/one", 0);
    xround x; x_round(hr, "k=v", &x, 0);
    a_dump(s);
    /* first round: the 401 is answered by FORCE_RETRY (decomp HttpSendRequest_Start AR_TYPE 0x12) */
    CHECKF(x.ex_ok, "ex err=%lu", x.ex_err);
    EXPECT_EQ(x.written, 3);
    CHECK(!x.end_ok);
    EXPECT_EQ(x.end_err, ERROR_INTERNET_FORCE_RETRY);
    EXPECT_EQ(srv_req_count(s), 1);
    CHECK(REQ_AUTH(s, 0) == NULL);
    EXPECT_EQ(x.status, 401);   /* the 401 is the current response until the resend (Win10 VM) */
    /* second round: the application re-sends the body, the client adds the Basic header */
    x_round(hr, "k=v", &x, 0);
    a_dump(s);
    CHECKF(x.ex_ok, "ex err=%lu", x.ex_err);
    CHECKF(x.end_ok, "end err=%lu", x.end_err);
    EXPECT_EQ(x.status, 200);
    char body[64]; size_t n = t_inet_read_all(hr, body, sizeof body, NULL); body[n < sizeof body ? n : sizeof body - 1] = 0;
    EXPECT_STR(body, "ok");
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) {
        EXPECT_STR(REQ_AUTH(s, 1), "Basic ZXh1OmV4cA==");
        EXPECT_STR(srv_req_method(s, 1), "POST");
        size_t bl = 0; const char *b = srv_req_body(s, 1, &bl);
        CHECKF(b && bl == 3 && !memcmp(b, "k=v", 3), "retry body len %zu", bl);
        EXPECT_STR(srv_req_header(s, 1, "Content-Length"), "3");
    }
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ex_basic_request_option_creds_force_retry) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.challenge = CH_BASIC_X; g.accept[0] = a_basic("optu", "optp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    HINTERNET hr = x_open(hc, "POST", "/ex/opt", 0);
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_USERNAME, "optu", 4));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PASSWORD, "optp", 4));
    xround x; int fr = 0; int rounds = x_loop(hr, "abc", &x, 0, &fr);
    a_dump(s);
    EXPECT_EQ(rounds, 2); EXPECT_EQ(fr, 1);
    CHECKF(x.end_ok, "end err=%lu", x.end_err);
    EXPECT_EQ(x.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_AUTH(s, 1), a_basic("optu", "optp"));
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ex_no_creds_401_is_normal_completion) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.challenge = CH_BASIC_X; g.accept[0] = a_basic("a", "b");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    HINTERNET hr = x_open(hc, "POST", "/ex/nocreds", 0);
    xround x; x_round(hr, "zz", &x, 0);
    CHECKF(x.ex_ok, "ex err=%lu", x.ex_err);
    CHECKF(x.end_ok, "end err=%lu", x.end_err);
    EXPECT_EQ(x.status, 401);
    char body[64]; size_t n = t_inet_read_all(hr, body, sizeof body, NULL); body[n < sizeof body ? n : sizeof body - 1] = 0;
    EXPECT_STR(body, "denied");
    EXPECT_EQ(srv_req_count(s), 1);
    char b[128]; DWORD idx = 0;
    CHECK(a_query(hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_STR(b, "Basic realm=\"i7ex\"");
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ex_no_auth_flag_no_force_retry) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.challenge = CH_BASIC_X; g.accept[0] = a_basic("nu", "np");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "nu", "np");
    HINTERNET hr = x_open(hc, "POST", "/ex/noauth", T_INET_FRESH | INTERNET_FLAG_NO_AUTH);
    xround x; x_round(hr, "q", &x, 0);
    /* decomp: the FORCE_RETRY hand-back is skipped when (0x4f4 & 0x40000) (NO_AUTH) is set */
    CHECKF(x.end_ok, "end err=%lu", x.end_err);
    EXPECT_EQ(x.status, 401);
    EXPECT_EQ(srv_req_count(s), 1);
    CHECK(REQ_AUTH(s, 0) == NULL);
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ex_wide_apis_force_retry) {
    REQUIRE(U(HttpSendRequestExW)); REQUIRE(U(HttpEndRequestW));
    gate g = {0}; g.challenge = CH_BASIC_X; g.accept[0] = a_basic("wu", "wp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectW)(hi, L"127.0.0.1", srv_port(s), L"wu", L"wp", INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestW)(hc, L"PUT", L"/ex/wide", NULL, NULL, NULL, T_INET_FRESH, 0);
    xround x; int fr = 0; int rounds = x_loop(hr, "wide-body", &x, 1, &fr);
    a_dump(s);
    EXPECT_EQ(rounds, 2); EXPECT_EQ(fr, 1);
    CHECKF(x.end_ok, "end err=%lu", x.end_err);
    EXPECT_EQ(x.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) {
        EXPECT_STR(REQ_AUTH(s, 1), a_basic("wu", "wp"));
        size_t bl = 0; const char *b = srv_req_body(s, 1, &bl);
        CHECKF(b && bl == 9 && !memcmp(b, "wide-body", 9), "body len %zu", bl);
    }
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ex_wrong_creds_bounded) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.challenge = CH_BASIC_X; g.accept[0] = a_basic("right", "right");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "wrong", "wrong");
    HINTERNET hr = x_open(hc, "POST", "/ex/wrong", 0);
    xround x; int fr = 0; int rounds = x_loop(hr, "w", &x, 0, &fr);
    a_dump(s);
    t_note("wrong creds via Ex: rounds=%d force_retries=%d end_ok=%d err=%lu status=%lu requests=%d", rounds, fr, x.end_ok, x.end_err, x.status, srv_req_count(s));
    CHECK(rounds < 4);
    /* Win10 VM: one FORCE_RETRY, then the second 401 is a normal completion */
    EXPECT_EQ(rounds, 2); EXPECT_EQ(fr, 1);
    CHECKF(x.end_ok, "end err=%lu", x.end_err);
    EXPECT_EQ(x.status, 401);
    EXPECT_EQ(srv_req_count(s), rounds);
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_AUTH(s, 1), a_basic("wrong", "wrong"));
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ex_digest_force_retry) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g; dgate(&g, CH_DIGEST_X, "dxu", "dx pass"); g.nonce = X_NONCE;
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "dxu", "dx pass");
    HINTERNET hr = x_open(hc, "POST", "/ex/digest?a=1", 0);
    xround x; int fr = 0; int rounds = x_loop(hr, "digest-body", &x, 0, &fr);
    a_dump(s);
    EXPECT_EQ(rounds, 2); EXPECT_EQ(fr, 1);
    CHECKF(x.end_ok, "end err=%lu", x.end_err);
    EXPECT_EQ(x.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) digest_check_recorded(s, 1, "dxu", "i7digest", "dx pass", 0, "auth");
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ex_get_without_body) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.challenge = CH_BASIC_X; g.accept[0] = a_basic("gu", "gp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "gu", "gp");
    HINTERNET hr = x_open(hc, "GET", "/ex/get", 0);
    xround x; int fr = 0; int rounds = x_loop(hr, NULL, &x, 0, &fr);
    a_dump(s);
    EXPECT_EQ(rounds, 2); EXPECT_EQ(fr, 1);
    EXPECT_EQ(x.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    for (int i = 0; i < srv_req_count(s) && i < 2; i++) EXPECT_STR(srv_req_method(s, i), "GET");
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_AUTH(s, 1), a_basic("gu", "gp"));
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ex_preemptive_after_success_no_force_retry) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.challenge = CH_BASIC_X; g.accept[0] = a_basic("pu", "pp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "pu", "pp");
    HINTERNET hr = x_open(hc, "POST", "/ex/pre/a", 0);
    xround x; int fr = 0; x_loop(hr, "1", &x, 0, &fr);
    EXPECT_EQ(x.status, 200);
    { char tmp[16]; t_inet_read_all(hr, tmp, sizeof tmp, NULL); }
    a_close(hr);
    int before = srv_req_count(s);
    hr = x_open(hc, "POST", "/ex/pre/b", 0);
    x_round(hr, "2", &x, 0);
    a_dump(s);
    /* the credential cache supplies the header on the first leg of the second request (cache.c, Win10 VM) */
    CHECKF(x.end_ok, "end err=%lu", x.end_err);
    EXPECT_EQ(x.status, 200);
    EXPECT_EQ(srv_req_count(s), before + 1);
    if (srv_req_count(s) > before) EXPECT_STR(REQ_AUTH(s, before), a_basic("pu", "pp"));
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ex_status_and_headers_after_force_retry) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.challenge = CH_BASIC_X; g.accept[0] = a_basic("su", "sp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "su", "sp");
    HINTERNET hr = x_open(hc, "POST", "/ex/st", 0);
    xround x; x_round(hr, "s", &x, 0);
    EXPECT_EQ(x.end_err, ERROR_INTERNET_FORCE_RETRY);
    char b[128]; DWORD idx = 0; int have = a_query(hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b);
    DWORD qe = have ? 0 : GetLastError();
    t_note("after FORCE_RETRY: status=%lu www-auth query=%d [%s] err=%lu", x.status, have, have ? b : "", qe);
    char rb[32]; DWORD rd = 0; BOOL rok = U(InternetReadFile)(hr, rb, sizeof rb, &rd);
    /* Win10 VM: the 401 response stays fully queryable and its body readable before the resend */
    EXPECT_EQ(x.status, 401);
    CHECK(have); EXPECT_STR(b, "Basic realm=\"i7ex\"");
    CHECK(rok); EXPECT_EQ(rd, 6); CHECK(rd == 6 && !memcmp(rb, "denied", 6));
    x_round(hr, "s", &x, 0);
    EXPECT_EQ(x.status, 200);
    idx = 0; SET_ERR(0);
    CHECK(!a_query(hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b));
    EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ex_resend_with_plain_httpsendrequest) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA)); REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC_X; g.accept[0] = a_basic("mu", "mp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "mu", "mp");
    HINTERNET hr = x_open(hc, "POST", "/ex/mixed", 0);
    xround x; x_round(hr, "mix", &x, 0);
    EXPECT_EQ(x.end_err, ERROR_INTERNET_FORCE_RETRY);
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, "mix", 3);
    DWORD e = ok ? 0 : GetLastError();
    a_dump(s);
    CHECKF(ok, "err=%lu", e);
    EXPECT_EQ(a_status(hr), 200);
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_AUTH(s, 1), a_basic("mu", "mp"));
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ex_ntlm_custom_gate_rounds) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.challenge = "WWW-Authenticate: NTLM\r\n"; g.ntlm_mode = 1; g.pass = "Ex-Secret9";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "exntlm", "Ex-Secret9");
    HINTERNET hr = x_open(hc, "POST", "/ex/ntlm", 0);
    xround x; int fr = 0; int rounds = x_loop(hr, "ntlm-body", &x, 0, &fr);
    a_dump(s);
    t_note("NTLM via Ex: rounds=%d force_retries=%d status=%lu requests=%d v2ok=%d", rounds, fr, x.status, srv_req_count(s), g.ntlm_v2_ok);
    CHECKF(x.end_ok, "end err=%lu", x.end_err);
    EXPECT_EQ(x.status, 200);
    EXPECT_EQ(g.ntlm_v2_ok, 1);
    EXPECT_STR(g.ntlm_user, "exntlm");
    /* Win10 VM: one FORCE_RETRY per leg (type 1, then type 3) */
    EXPECT_EQ(rounds, 3); EXPECT_EQ(fr, 2);
    EXPECT_EQ(srv_req_count(s), 3);
    /* the last leg carries the body */
    int last = srv_req_count(s) - 1;
    if (last >= 0) { size_t bl = 0; const char *b = srv_req_body(s, last, &bl); CHECKF(b && bl == 9 && !memcmp(b, "ntlm-body", 9), "last body len %zu", bl); }
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

/* proxy 407 through HttpSendRequestEx: same FORCE_RETRY contract */
static HINTERNET x_proxy_session(srv *s) {
    t_net_prepare();
    char px[64]; snprintf(px, sizeof px, "127.0.0.1:%u", srv_port(s));
    HINTERNET hi = U(InternetOpenA)("i7exproxy", INTERNET_OPEN_TYPE_PROXY, px, NULL, 0);
    DWORD to = 5000;
    if (hi) { U(InternetSetOptionA)(hi, INTERNET_OPTION_CONNECT_TIMEOUT, &to, 4); U(InternetSetOptionA)(hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, 4); U(InternetSetOptionA)(hi, INTERNET_OPTION_SEND_TIMEOUT, &to, 4); }
    return hi;
}

TEST(auth_ex_proxy_407_force_retry) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC_X; g.accept[0] = a_basic("pxu", "pxp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = x_proxy_session(s);
    HINTERNET hc = U(InternetConnectA)(hi, "i7origin.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = x_open(hc, "POST", "/ex/proxy", 0);
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_USERNAME, "pxu", 3));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_PASSWORD, "pxp", 3));
    xround x; int fr = 0; int rounds = x_loop(hr, "pbody", &x, 0, &fr);
    a_dump(s);
    EXPECT_EQ(rounds, 2); EXPECT_EQ(fr, 1);
    CHECKF(x.end_ok, "end err=%lu", x.end_err);
    EXPECT_EQ(x.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) {
        EXPECT_STR(REQ_PAUTH(s, 1), a_basic("pxu", "pxp"));
        CHECK(REQ_AUTH(s, 1) == NULL);
        EXPECT_STR(srv_req_line(s, 1), "POST http://i7origin.invalid/ex/proxy HTTP/1.1");
    }
    a_close(hr); a_close(hc); a_close(hi); srv_stop(s);
}

TEST(auth_ex_proxy_407_no_creds_normal_completion) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC_X; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = x_proxy_session(s);
    HINTERNET hc = U(InternetConnectA)(hi, "i7origin.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = x_open(hc, "POST", "/ex/proxy-nc", 0);
    xround x; x_round(hr, "p", &x, 0);
    CHECKF(x.end_ok, "end err=%lu", x.end_err);
    EXPECT_EQ(x.status, 407);
    EXPECT_EQ(srv_req_count(s), 1);
    a_close(hr); a_close(hc); a_close(hi); srv_stop(s);
}

TEST(auth_ex_end_request_without_send_ex) {
    REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.challenge = CH_BASIC_X; g.accept[0] = a_basic("a", "b");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "a", "b");
    HINTERNET hr = x_open(hc, "POST", "/ex/noex", 0);
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpEndRequestA)(hr, NULL, 0, 0);
    DWORD e = ok ? 0 : GetLastError();
    t_note("HttpEndRequest before HttpSendRequestEx: ok=%d err=%lu (%s)", ok, e, t_inet_errname(e));
    CHECK(!ok);
    EXPECT_EQ(e, ERROR_INTERNET_OPERATION_CANCELLED);   /* 12017 (Win10 VM) */
    EXPECT_EQ(srv_req_count(s), 0);
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ex_chunked_upload_force_retry) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    gate g = {0}; g.challenge = CH_BASIC_X; g.accept[0] = a_basic("cu", "cp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "cu", "cp");
    HINTERNET hr = x_open(hc, "POST", "/ex/fixed2", 0);
    /* two writes for one declared length */
    int rounds = 0, fr = 0; xround x; memset(&x, 0, sizeof x);
    for (; rounds < 4; ) {
        INTERNET_BUFFERSA b; memset(&b, 0, sizeof b); b.dwStructSize = sizeof b; b.dwBufferTotal = 6;
        x.ex_ok = U(HttpSendRequestExA)(hr, &b, NULL, 0, 0); rounds++;
        if (!x.ex_ok) { x.ex_err = GetLastError(); break; }
        DWORD w = 0; U(InternetWriteFile)(hr, "abc", 3, &w); U(InternetWriteFile)(hr, "def", 3, &w);
        x.end_ok = U(HttpEndRequestA)(hr, NULL, 0, 0); x.end_err = x.end_ok ? 0 : GetLastError();
        if (!x.end_ok && x.end_err == ERROR_INTERNET_FORCE_RETRY) { fr++; continue; }
        break;
    }
    x.status = a_status(hr);
    a_dump(s);
    EXPECT_EQ(rounds, 2); EXPECT_EQ(fr, 1);
    EXPECT_EQ(x.status, 200);
    if (srv_req_count(s) >= 2) {
        size_t bl = 0; const char *b = srv_req_body(s, 1, &bl);
        CHECKF(b && bl == 6 && !memcmp(b, "abcdef", 6), "body len %zu", bl);
        EXPECT_STR(REQ_AUTH(s, 1), a_basic("cu", "cp"));
    }
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}
