/* http_auth: HttpQueryInfo on authentication headers (WWW-Authenticate, Proxy-Authenticate, Authorization,
 * Authentication-Info), A and W, by index, custom names, raw headers and the request-header view. */
#include "auth.h"
#include <stdlib.h>

#define CH_B "WWW-Authenticate: Basic realm=\"i7hq\"\r\n"

/* open + send without credentials; returns the request handle (401 expected), NULL on failure */
static HINTERNET hq_401(srv *s, HINTERNET *hi, HINTERNET *hc, const char *path, const char *hdrs) {
    *hi = t_inet_open(NULL); *hc = a_connect(*hi, s, NULL, NULL);
    HINTERNET hr = U(HttpOpenRequestA)(*hc, "GET", path, NULL, NULL, NULL, T_INET_FRESH, 0);
    if (!hr) return NULL;
    if (!U(HttpSendRequestA)(hr, hdrs, hdrs ? (DWORD)-1 : 0, NULL, 0)) t_note("send failed %lu", GetLastError());
    return hr;
}
static void hq_close(HINTERNET hr, HINTERNET hc, HINTERNET hi) { a_close(hr); a_close(hc); t_inet_close(hi); }

TEST(auth_hq_www_authenticate_a_sizes) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.challenge = CH_B; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi, hc, hr = hq_401(s, &hi, &hc, "/hq/a", NULL);
    const char *want = "Basic realm=\"i7hq\""; DWORD wl = (DWORD)strlen(want);
    char b[64]; DWORD l = sizeof b, idx = 0;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_WWW_AUTHENTICATE, b, &l, &idx));
    EXPECT_STR(b, want); EXPECT_EQ(l, wl); EXPECT_EQ(idx, 1);
    /* exact size without room for the NUL -> 122, size with NUL, index unchanged */
    l = wl; idx = 0; SET_ERR(0);
    CHECK(!U(HttpQueryInfoA)(hr, HTTP_QUERY_WWW_AUTHENTICATE, b, &l, &idx));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, wl + 1); EXPECT_EQ(idx, 0);
    l = wl + 1; idx = 0;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_WWW_AUTHENTICATE, b, &l, &idx)); EXPECT_EQ(l, wl);
    /* NULL buffer, zero length -> 122 and required size */
    l = 0; idx = 0; SET_ERR(0);
    CHECK(!U(HttpQueryInfoA)(hr, HTTP_QUERY_WWW_AUTHENTICATE, NULL, &l, &idx));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, wl + 1);
    /* NULL index pointer = first occurrence */
    l = sizeof b; CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_WWW_AUTHENTICATE, b, &l, NULL)); EXPECT_STR(b, want);
    hq_close(hr, hc, hi); srv_stop(s);
}

TEST(auth_hq_www_authenticate_w_sizes) {
    REQUIRE(U(HttpQueryInfoW));
    gate g = {0}; g.challenge = CH_B; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi, hc, hr = hq_401(s, &hi, &hc, "/hq/w", NULL);
    const WCHAR *want = L"Basic realm=\"i7hq\""; DWORD wc = (DWORD)lstrlenW(want);
    WCHAR b[64]; DWORD l = sizeof b, idx = 0;
    CHECK(U(HttpQueryInfoW)(hr, HTTP_QUERY_WWW_AUTHENTICATE, b, &l, &idx));
    EXPECT_WSTR(b, want); EXPECT_EQ(l, wc * 2); EXPECT_EQ(idx, 1);
    l = wc * 2; idx = 0; SET_ERR(0);
    CHECK(!U(HttpQueryInfoW)(hr, HTTP_QUERY_WWW_AUTHENTICATE, b, &l, &idx));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, (wc + 1) * 2);
    l = 0; idx = 0; SET_ERR(0);
    CHECK(!U(HttpQueryInfoW)(hr, HTTP_QUERY_WWW_AUTHENTICATE, NULL, &l, &idx));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, (wc + 1) * 2);
    hq_close(hr, hc, hi); srv_stop(s);
}

TEST(auth_hq_multiple_challenges_mixed_name_case) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.accept[0] = "never";
    g.challenge = "WWW-Authenticate: Basic realm=\"one\"\r\nwww-authenticate: Digest realm=\"two\", nonce=\"abc\"\r\nWWW-AUTHENTICATE: NTLM\r\nWww-Authenticate: Negotiate\r\n";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi, hc, hr = hq_401(s, &hi, &hc, "/hq/multi", NULL);
    static const char *want[] = { "Basic realm=\"one\"", "Digest realm=\"two\", nonce=\"abc\"", "NTLM", "Negotiate" };
    DWORD idx = 0; char b[128];
    for (int i = 0; i < 4; i++) {
        CHECKF(a_query(hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b), "index %d", i);
        CHECKF(!strcmp(b, want[i]), "index %d: [%s] want [%s]", i, b, want[i]);
        EXPECT_EQ(idx, (DWORD)(i + 1));
    }
    SET_ERR(0); CHECK(!a_query(hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_EQ(idx, 4);
    /* explicit index into the middle */
    idx = 2; CHECK(a_query(hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_STR(b, "NTLM"); EXPECT_EQ(idx, 3);
    idx = 9; SET_ERR(0); CHECK(!a_query(hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    hq_close(hr, hc, hi); srv_stop(s);
}

TEST(auth_hq_comma_list_is_one_header) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.accept[0] = "never"; g.challenge = "WWW-Authenticate: Basic realm=\"x\", NTLM, Negotiate\r\n";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi, hc, hr = hq_401(s, &hi, &hc, "/hq/comma", NULL);
    DWORD idx = 0; char b[128];
    CHECK(a_query(hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_STR(b, "Basic realm=\"x\", NTLM, Negotiate");
    SET_ERR(0); CHECK(!a_query(hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    hq_close(hr, hc, hi); srv_stop(s);
}

TEST(auth_hq_custom_name_lookup) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.challenge = CH_B; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi, hc, hr = hq_401(s, &hi, &hc, "/hq/custom", NULL);
    static const char *names[] = { "WWW-Authenticate", "www-authenticate", "Www-AUTHENTICATE" };
    for (int i = 0; i < 3; i++) {
        char b[128]; snprintf(b, sizeof b, "%s", names[i]); DWORD l = sizeof b, idx = 0;
        CHECKF(U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM, b, &l, &idx), "%s err=%lu", names[i], GetLastError());
        CHECKF(!strcmp(b, "Basic realm=\"i7hq\""), "%s -> [%s]", names[i], b);
    }
    char b[128]; snprintf(b, sizeof b, "Proxy-Authenticate"); DWORD l = sizeof b, idx = 0; SET_ERR(0);
    CHECK(!U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM, b, &l, &idx)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    hq_close(hr, hc, hi); srv_stop(s);
}

TEST(auth_hq_raw_headers_contain_challenge) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.challenge = CH_B; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi, hc, hr = hq_401(s, &hi, &hc, "/hq/raw", NULL);
    char b[2048]; DWORD idx = 0;
    CHECK(a_query(hr, HTTP_QUERY_RAW_HEADERS_CRLF, &idx, b, sizeof b));
    CHECKF(!strncmp(b, "HTTP/1.1 401 Unauthorized\r\n", 27), "raw starts [%.40s]", b);
    CHECKF(strstr(b, "\r\nWWW-Authenticate: Basic realm=\"i7hq\"\r\n") != NULL, "raw=[%s]", b);
    /* RAW_HEADERS: NUL-separated, double NUL at the end */
    DWORD l = sizeof b; idx = 0;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_RAW_HEADERS, b, &l, &idx));
    int found = 0; for (char *p = b; *p && p < b + l; p += strlen(p) + 1) if (!strcmp(p, "WWW-Authenticate: Basic realm=\"i7hq\"")) found = 1;
    CHECK(found);
    hq_close(hr, hc, hi); srv_stop(s);
}

TEST(auth_hq_proxy_authenticate_absent_on_401) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.challenge = CH_B; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi, hc, hr = hq_401(s, &hi, &hc, "/hq/noproxy", NULL);
    char b[128]; DWORD idx = 0; SET_ERR(0);
    CHECK(!a_query(hr, HTTP_QUERY_PROXY_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    idx = 0; SET_ERR(0);
    CHECK(!a_query(hr, HTTP_QUERY_AUTHORIZATION, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    idx = 0; SET_ERR(0);
    CHECK(!a_query(hr, HTTP_QUERY_PROXY_AUTHORIZATION, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    idx = 0; CHECK(a_query(hr, HTTP_QUERY_STATUS_TEXT, &idx, b, sizeof b)); EXPECT_STR(b, "Unauthorized");
    idx = 0; CHECK(a_query(hr, HTTP_QUERY_STATUS_CODE, &idx, b, sizeof b)); EXPECT_STR(b, "401");
    DWORD code = 0, l = sizeof code;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &code, &l, NULL)); EXPECT_EQ(code, 401); EXPECT_EQ(l, 4);
    hq_close(hr, hc, hi); srv_stop(s);
}

TEST(auth_hq_caller_authorization_dropped_from_request_view) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.challenge = CH_B; g.accept[0] = "Bearer i7token";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi, hc, hr = hq_401(s, &hi, &hc, "/hq/bearer", "Authorization: Bearer i7token\r\n");
    EXPECT_EQ(a_status(hr), 200);
    EXPECT_EQ(srv_req_count(s), 1);
    EXPECT_STR(REQ_AUTH(s, 0), "Bearer i7token");
    /* Win10 VM: the Authorization passed to HttpSendRequest is on the wire but not kept in the request-header view
     * (same as the one wininet adds on a retry, basic.c auth_basic_query_request_authorization_header) */
    char b[128]; DWORD idx = 0; SET_ERR(0);
    CHECK(!a_query(hr, HTTP_QUERY_AUTHORIZATION | HTTP_QUERY_FLAG_REQUEST_HEADERS, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    idx = 0; snprintf(b, sizeof b, "authorization"); DWORD l = sizeof b; SET_ERR(0);
    CHECK(!U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_REQUEST_HEADERS, b, &l, &idx)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    /* response view has no Authorization */
    idx = 0; SET_ERR(0); CHECK(!a_query(hr, HTTP_QUERY_AUTHORIZATION, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    /* raw request headers carry it too */
    char raw[2048]; idx = 0;
    CHECK(a_query(hr, HTTP_QUERY_RAW_HEADERS_CRLF | HTTP_QUERY_FLAG_REQUEST_HEADERS, &idx, raw, sizeof raw));
    CHECKF(strstr(raw, "Authorization") == NULL, "raw=[%s]", raw);
    CHECKF(!strncmp(raw, "GET /hq/bearer HTTP/1.1\r\n", 25), "raw=[%s]", raw);
    hq_close(hr, hc, hi); srv_stop(s);
}

TEST(auth_hq_caller_authorization_w_dropped_from_request_view) {
    REQUIRE(U(HttpQueryInfoW)); REQUIRE(U(HttpSendRequestW));
    gate g = {0}; g.challenge = CH_B; g.accept[0] = "Bearer wtok";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    HINTERNET hr = U(HttpOpenRequestW)(hc, L"GET", L"/hq/wbearer", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpSendRequestW)(hr, L"Authorization: Bearer wtok\r\n", (DWORD)-1, NULL, 0));
    EXPECT_EQ(a_status(hr), 200);
    EXPECT_STR(REQ_AUTH(s, 0), "Bearer wtok");
    WCHAR b[64]; DWORD l = sizeof b, idx = 0; SET_ERR(0);
    CHECK(!U(HttpQueryInfoW)(hr, HTTP_QUERY_AUTHORIZATION | HTTP_QUERY_FLAG_REQUEST_HEADERS, b, &l, &idx));
    EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);   /* Win10 VM */
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_hq_no_authorization_in_request_view_without_header) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.challenge = CH_B; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi, hc, hr = hq_401(s, &hi, &hc, "/hq/noreq", NULL);
    char b[128]; DWORD idx = 0; SET_ERR(0);
    CHECK(!a_query(hr, HTTP_QUERY_AUTHORIZATION | HTTP_QUERY_FLAG_REQUEST_HEADERS, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    idx = 0; SET_ERR(0);
    CHECK(!a_query(hr, HTTP_QUERY_WWW_AUTHENTICATE | HTTP_QUERY_FLAG_REQUEST_HEADERS, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    hq_close(hr, hc, hi); srv_stop(s);
}

TEST(auth_hq_authentication_info_after_digest) {
    REQUIRE(U(HttpQueryInfoA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"\r\n", "ai", "aipw");
    g.ok_hdrs = "Authentication-Info: rspauth=\"0123456789abcdef0123456789abcdef\", qop=auth, nc=00000001\r\n";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "ai", "aipw");
    areq q = {0}; q.path = "/hq/ainfo"; ares r; a_send(hc, &q, &r, 1);
    EXPECT_EQ(r.status, 200);
    char b[256]; snprintf(b, sizeof b, "Authentication-Info"); DWORD l = sizeof b, idx = 0;
    CHECK(U(HttpQueryInfoA)(r.hr, HTTP_QUERY_CUSTOM, b, &l, &idx));
    EXPECT_STR(b, "rspauth=\"0123456789abcdef0123456789abcdef\", qop=auth, nc=00000001");
    /* the 200 replaced the 401 headers */
    idx = 0; SET_ERR(0); CHECK(!a_query(r.hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_hq_long_challenge_value) {
    REQUIRE(U(HttpQueryInfoA));
    static char ch[3200], want[3200];
    char realm[3001]; for (int i = 0; i < 3000; i++) realm[i] = (char)('a' + i % 26); realm[3000] = 0;
    snprintf(want, sizeof want, "Basic realm=\"%s\"", realm);
    snprintf(ch, sizeof ch, "WWW-Authenticate: %s\r\n", want);
    gate g = {0}; g.challenge = ch; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi, hc, hr = hq_401(s, &hi, &hc, "/hq/long", NULL);
    DWORD l = 0, idx = 0; SET_ERR(0);
    CHECK(!U(HttpQueryInfoA)(hr, HTTP_QUERY_WWW_AUTHENTICATE, NULL, &l, &idx)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, (DWORD)strlen(want) + 1);
    char *b = malloc(l + 16); DWORD l2 = l; idx = 0;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_WWW_AUTHENTICATE, b, &l2, &idx));
    EXPECT_EQ(l2, (DWORD)strlen(want));
    CHECK(!strcmp(b, want));
    free(b);
    hq_close(hr, hc, hi); srv_stop(s);
}

TEST(auth_hq_query_before_send) {
    REQUIRE(U(HttpQueryInfoA));
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 9, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/never", NULL, NULL, NULL, T_INET_FRESH, 0);
    REQUIRE(hr);
    char b[128]; DWORD idx = 0; SET_ERR(0);
    int ok = a_query(hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b); DWORD e = GetLastError();
    t_note("WWW-Authenticate before send: ok=%d err=%lu (%s)", ok, e, t_inet_errname(e));
    CHECK(!ok);
    /* request headers exist before send: a caller header added with HttpAddRequestHeaders is visible */
    CHECK(U(HttpAddRequestHeadersA)(hr, "Authorization: Basic Zm9vOmJhcg==\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    idx = 0; CHECK(a_query(hr, HTTP_QUERY_AUTHORIZATION | HTTP_QUERY_FLAG_REQUEST_HEADERS, &idx, b, sizeof b));
    EXPECT_STR(b, "Basic Zm9vOmJhcg==");
    a_close(hr); a_close(hc); t_inet_close(hi);
}

TEST(auth_hq_add_request_headers_authorization_sent) {
    REQUIRE(U(HttpAddRequestHeadersA));
    gate g = {0}; g.challenge = CH_B; g.accept[0] = a_basic("added", "hdr");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/hq/added", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpAddRequestHeadersA)(hr, "Authorization: Basic YWRkZWQ6aGRy\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_EQ(a_status(hr), 200);
    EXPECT_EQ(srv_req_count(s), 1);
    EXPECT_STR(REQ_AUTH(s, 0), "Basic YWRkZWQ6aGRy");
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Authorization"), 1);
    char b[128]; DWORD idx = 0; int kept = a_query(hr, HTTP_QUERY_AUTHORIZATION | HTTP_QUERY_FLAG_REQUEST_HEADERS, &idx, b, sizeof b);
    t_note("HttpAddRequestHeaders Authorization in the request view after send: %d [%s]", kept, kept ? b : "");
    CHECK(!kept);   /* Win10 VM: dropped after the send, like a HttpSendRequest header */
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_hq_add_request_headers_replace_authorization) {
    REQUIRE(U(HttpAddRequestHeadersA));
    gate g = {0}; g.challenge = CH_B; g.accept[0] = "Basic c2Vjb25k";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/hq/replace", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpAddRequestHeadersA)(hr, "Authorization: Basic Zmlyc3Q=\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(U(HttpAddRequestHeadersA)(hr, "Authorization: Basic c2Vjb25k\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE));
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_EQ(a_status(hr), 200);
    EXPECT_STR(REQ_AUTH(s, 0), "Basic c2Vjb25k");
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Authorization"), 1);
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_hq_proxy_authorization_caller_header) {
    REQUIRE(U(HttpSendRequestA));
    /* a caller-supplied Proxy-Authorization to a direct origin is sent as given */
    gate g = {0}; g.challenge = CH_B; g.accept[0] = a_basic("u", "p");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/hq/pauth"; q.hdrs = "Proxy-Authorization: Basic eHg6eXk=\r\n"; q.cuser = "u"; q.cpass = "p";
    ares r; a_once(s, &q, &r);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    EXPECT_STR(REQ_PAUTH(s, 0), "Basic eHg6eXk=");
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_PAUTH(s, 1), "Basic eHg6eXk=");   /* kept on the retry (Win10 VM) */
    srv_stop(s);
}

TEST(auth_hq_status_code_flag_number_after_retry) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.challenge = CH_B; g.accept[0] = a_basic("n", "m");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "n", "m");
    areq q = {0}; q.path = "/hq/num"; ares r; a_send(hc, &q, &r, 1);
    DWORD code = 0, l = sizeof code;
    CHECK(U(HttpQueryInfoA)(r.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &code, &l, NULL)); EXPECT_EQ(code, 200);
    char b[64]; DWORD idx = 0; CHECK(a_query(r.hr, HTTP_QUERY_STATUS_TEXT, &idx, b, sizeof b)); EXPECT_STR(b, "OK");
    idx = 0; CHECK(a_query(r.hr, HTTP_QUERY_CONTENT_LENGTH, &idx, b, sizeof b)); EXPECT_STR(b, "2");
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}
