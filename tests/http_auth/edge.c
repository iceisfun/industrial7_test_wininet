/* http_auth: framing and connection edge cases around the 401 retry (scripted servers: the first response is the
 * challenge in some framing, the second request is recorded and answered 200). */
#include "auth.h"

#define CH "WWW-Authenticate: Basic realm=\"edge\"\r\n"
#define B64UP "Basic dXNlcjpwYXNz"

static void run_script(const srv_step *st, int n, const char *path, DWORD flags, ares *r, srv **out) {
    srv_script sc = { st, n }; srv_config cfg = { SRV_HTTP, &sc, 1 };
    *out = NULL; memset(r, 0, sizeof *r);
    if (srv_start(&cfg, out)) return;
    areq q = {0}; q.path = path; q.cuser = "user"; q.cpass = "pass"; q.flags = flags; a_once(*out, &q, r);
}
#define RUN(st, path, r, s) do { run_script(st, (int)(sizeof st / sizeof st[0]), path, 0, &r, &s); SRV_OR_SKIP(s); } while (0)

TEST(auth_edge_chunked_401_body) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_CHUNKED(401, CH, "denied-in-chunks", 3), S_HEAD(), S_REPLY(200, NULL, "fine"), S_LOOP_TO(2) };
    ares r; srv *s; RUN(st, "/ch", r, s);
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "fine");
    EXPECT_EQ(srv_req_count(s), 2);
    EXPECT_STR(REQ_AUTH(s, 1), B64UP);
    EXPECT_EQ(srv_req_conn(s, 0), srv_req_conn(s, 1));   /* chunked body drained, connection reused */
    srv_stop(s);
}

TEST(auth_edge_large_401_body_drained) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(401, CH, 65536, 0), S_HEAD(), S_REPLY(200, NULL, "fine"), S_LOOP_TO(2) };
    ares r; srv *s; RUN(st, "/big", r, s);
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "fine");
    EXPECT_EQ(srv_req_count(s), 2);
    EXPECT_STR(REQ_AUTH(s, 1), B64UP);
    EXPECT_EQ(srv_req_conn(s, 0), srv_req_conn(s, 1));   /* Win10 VM: drained, connection reused */
    srv_stop(s);
}

TEST(auth_edge_close_delimited_401) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st0[] = { S_HEAD(), S_REPLYF(401, CH, "closing", SRV_R_CLOSE) };
    static const srv_step st1[] = { S_HEAD(), S_REPLY(200, NULL, "fine"), S_LOOP() };
    static const srv_script sc[] = { SRV_SCRIPT(st0), SRV_SCRIPT(st1) };
    srv_config cfg = { SRV_HTTP, sc, 2 }; srv *s; START_OR_SKIP(&cfg, &s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pass"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "fine");
    EXPECT_EQ(srv_req_count(s), 2);
    EXPECT_STR(REQ_AUTH(s, 1), B64UP);
    CHECK(srv_req_conn(s, 0) != srv_req_conn(s, 1));
    srv_stop(s);
}

TEST(auth_edge_http10_401) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st0[] = { S_HEAD(), S_REPLYF(401, CH, "old", SRV_R_HTTP10 | SRV_R_CONN_CLOSE) };
    static const srv_step st1[] = { S_HEAD(), S_REPLY(200, NULL, "fine"), S_LOOP() };
    static const srv_script sc[] = { SRV_SCRIPT(st0), SRV_SCRIPT(st1) };
    srv_config cfg = { SRV_HTTP, sc, 2 }; srv *s; START_OR_SKIP(&cfg, &s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pass"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    EXPECT_STR(REQ_AUTH(s, 1), B64UP);
    srv_stop(s);
}

TEST(auth_edge_401_no_body_no_length) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 401 Unauthorized\r\n" CH "Content-Length: 0\r\n\r\n"), S_HEAD(), S_REPLY(200, NULL, "fine"), S_LOOP_TO(2) };
    ares r; srv *s; RUN(st, "/z", r, s);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    EXPECT_STR(REQ_AUTH(s, 1), B64UP);
    srv_stop(s);
}

TEST(auth_edge_redirect_then_401) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /target\r\n", ""), S_HEAD(), S_REPLY(401, CH, "no"), S_HEAD(), S_REPLY(200, NULL, "fine"), S_LOOP_TO(4) };
    ares r; srv *s; run_script(st, 7, "/start", T_INET_FRESH, &r, &s); SRV_OR_SKIP(s);
    a_dump(s);
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "fine");
    EXPECT_EQ(srv_req_count(s), 3);
    if (srv_req_count(s) >= 3) {
        EXPECT_STR(srv_req_target(s, 1), "/target"); CHECK(REQ_AUTH(s, 1) == NULL);
        EXPECT_STR(srv_req_target(s, 2), "/target"); EXPECT_STR(REQ_AUTH(s, 2), B64UP);
    }
    srv_stop(s);
}

TEST(auth_edge_401_then_redirect_keeps_auth_same_host) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, CH, "no"), S_HEAD(), S_REPLY(302, "Location: /moved/x\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "fine"), S_LOOP_TO(4) };
    ares r; srv *s; run_script(st, 7, "/orig/x", T_INET_FRESH, &r, &s); SRV_OR_SKIP(s);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 3);
    if (srv_req_count(s) >= 3) {
        EXPECT_STR(REQ_AUTH(s, 1), B64UP);
        EXPECT_STR(srv_req_target(s, 2), "/moved/x");
        CHECK(REQ_AUTH(s, 2) == NULL);   /* Win10 VM: other directory, no pre-authentication */
    }
    srv_stop(s);
}

TEST(auth_edge_redirect_cross_host_after_auth) {
    REQUIRE(U(HttpSendRequestA));
    /* same server reached as "localhost" after authenticating to 127.0.0.1: record whether Basic follows */
    static const srv_step st0[] = { S_HEAD(), S_REPLY(401, CH, "no"), S_HEAD(), S_REPLY(302, "Location: http://localhost:%P/elsewhere\r\n", ""), S_LOOP() };
    static const srv_step st1[] = { S_HEAD(), S_REPLY(200, NULL, "fine"), S_LOOP() };
    static const srv_script sc[] = { SRV_SCRIPT(st0), SRV_SCRIPT(st1) };
    srv_config cfg = { SRV_HTTP, sc, 2 }; srv *s; START_OR_SKIP(&cfg, &s);
    areq q = {0}; q.path = "/x"; q.cuser = "user"; q.cpass = "pass"; ares r; a_once(s, &q, &r);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 3);
    if (srv_req_count(s) >= 3) {
        CHECK(srv_req_header(s, 2, "Host") && !strncmp(srv_req_header(s, 2, "Host"), "localhost:", 10));
        CHECK(REQ_AUTH(s, 2) == NULL);   /* Win10 VM: credentials do not follow a redirect to another host name */
        CHECK(srv_req_conn(s, 2) != srv_req_conn(s, 1));
    }
    srv_stop(s);
}

TEST(auth_edge_401_status_text_and_content_length_query) {
    REQUIRE(U(HttpQueryInfoA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, CH "X-Reason: nope\r\n", "twelve chars"), S_LOOP() };
    srv *s = srv_http(st, 3); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    EXPECT_EQ(r.status, 401); EXPECT_STR(r.body, "twelve chars");
    DWORD cl = 0, l = sizeof cl; CHECK(U(HttpQueryInfoA)(r.hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &cl, &l, NULL)); EXPECT_EQ(cl, 12);
    char b[64]; DWORD idx = 0; strcpy(b, "X-Reason"); l = sizeof b; CHECK(U(HttpQueryInfoA)(r.hr, HTTP_QUERY_CUSTOM, b, &l, &idx)); EXPECT_STR(b, "nope");
    idx = 0; CHECK(a_query(r.hr, HTTP_QUERY_STATUS_CODE, &idx, b, sizeof b)); EXPECT_STR(b, "401");
    idx = 0; CHECK(a_query(r.hr, HTTP_QUERY_VERSION, &idx, b, sizeof b)); EXPECT_STR(b, "HTTP/1.1");
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_edge_server_revokes_after_success) {
    REQUIRE(U(HttpSendRequestA));
    /* 401 -> 200 (cached) -> next request pre-emptive gets 401 again -> record whether the client retries */
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, CH, "a"), S_HEAD(), S_REPLY(200, NULL, "ok1"), S_HEAD(), S_REPLY(401, CH, "revoked"),
                                   S_HEAD(), S_REPLY(401, CH, "still"), S_LOOP_TO(6) };
    srv *s = srv_http(st, 9); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pass");
    areq q = {0}; q.path = "/rv/a"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    a_send(hc, &q, &r, 0);
    a_dump(s);
    /* Win10 VM: a 401 to a pre-authenticated request is returned without another retry */
    EXPECT_EQ(r.status, 401); EXPECT_STR(r.body, "revoked"); EXPECT_EQ(srv_req_count(s), 3);
    if (srv_req_count(s) >= 3) EXPECT_STR(REQ_AUTH(s, 2), B64UP);
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_edge_open_url_userinfo_no_auth_flag) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, CH, "no"), S_HEAD(), S_REPLY(200, NULL, "fine"), S_LOOP_TO(2) };
    srv *s = srv_http(st, 5); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL);
    char url[200]; snprintf(url, sizeof url, "http://user:pass@%s/nf", srv_hostport(s));
    char body[64]; size_t n; DWORD err;
    int code = t_http_get(hi, url, NULL, T_INET_FRESH | INTERNET_FLAG_NO_AUTH, body, sizeof body, &n, &err);
    a_dump(s);
    EXPECT_EQ(code, 401);
    EXPECT_EQ(srv_req_count(s), 1);
    t_inet_close(hi); srv_stop(s);
}

TEST(auth_edge_authorization_header_position) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, CH, "no"), S_HEAD(), S_REPLY(200, NULL, "fine"), S_LOOP_TO(2) };
    ares r; srv *s; RUN(st, "/pos", r, s);
    if (srv_req_count(s) >= 2) {
        char line[512] = ""; size_t o = 0;
        for (int h = 0; h < srv_req_header_count(s, 1) && o + 40 < sizeof line; h++) o += snprintf(line + o, sizeof line - o, "%s|", srv_req_header_name(s, 1, h));
        char line0[512] = ""; o = 0;
        for (int h = 0; h < srv_req_header_count(s, 0) && o + 40 < sizeof line0; h++) o += snprintf(line0 + o, sizeof line0 - o, "%s|", srv_req_header_name(s, 0, h));
        t_note("first header order: %s retry: %s", line0, line);
        EXPECT_STR(line, "User-Agent|Host|Cache-Control|Connection|Authorization|");   /* Win10 VM */
        EXPECT_EQ(srv_req_header_occurrences(s, 1, "Authorization"), 1);
    }
    srv_stop(s);
}
