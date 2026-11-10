/* http_auth: credential caching and pre-authentication across requests (PWC list).
 * After a successful Basic exchange WinINet remembers the credentials per server/realm/path and sends them
 * pre-emptively on later requests. Each test uses its own server (own port), so nothing leaks between tests. */
#include "auth.h"

#define CH_BASIC "WWW-Authenticate: Basic realm=\"i7\"\r\n"

static int n_with_auth(srv *s, int from) { int k = 0; for (int i = from; i < srv_req_count(s); i++) if (REQ_AUTH(s, i)) k++; return k; }

TEST(auth_cache_second_request_same_path_preemptive) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pass");
    areq q = {0}; q.path = "/dir/a"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200); EXPECT_EQ(srv_req_count(s), 2);
    a_send(hc, &q, &r, 0);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 3);
    EXPECT_STR(REQ_AUTH(s, 2), "Basic dXNlcjpwYXNz");
    EXPECT_EQ(g.n_deny, 1);
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_cache_sibling_path_same_directory) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pass");
    areq q = {0}; q.path = "/dir/a"; ares r; a_send(hc, &q, &r, 0);
    q.path = "/dir/b"; a_send(hc, &q, &r, 0);
    q.path = "/dir/sub/c"; ares r3; a_send(hc, &q, &r3, 0);
    a_dump(s);
    EXPECT_EQ(r.status, 200); EXPECT_EQ(r3.status, 200);
    EXPECT_EQ(srv_req_count(s), 4);
    EXPECT_STR(srv_req_target(s, 2), "/dir/b"); EXPECT_STR(REQ_AUTH(s, 2), "Basic dXNlcjpwYXNz");
    EXPECT_STR(srv_req_target(s, 3), "/dir/sub/c"); EXPECT_STR(REQ_AUTH(s, 3), "Basic dXNlcjpwYXNz");
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_cache_other_directory) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pass");
    areq q = {0}; q.path = "/dir/a"; ares r; a_send(hc, &q, &r, 0);
    int before = srv_req_count(s);
    q.path = "/other/x"; a_send(hc, &q, &r, 0);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    t_note("other directory after /dir/ auth: %d more requests, first auth=%s", srv_req_count(s) - before,
           REQ_AUTH(s, before) ? REQ_AUTH(s, before) : "(none)");
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_cache_parent_directory) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pass");
    areq q = {0}; q.path = "/p/q/a"; ares r; a_send(hc, &q, &r, 0);
    int before = srv_req_count(s);
    q.path = "/p/b"; a_send(hc, &q, &r, 0);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    t_note("parent directory after /p/q/ auth: %d more requests, first auth=%s", srv_req_count(s) - before,
           REQ_AUTH(s, before) ? REQ_AUTH(s, before) : "(none)");
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_cache_new_connect_handle_no_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pass");
    areq q = {0}; q.path = "/c/a"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    a_close(hc);
    int before = srv_req_count(s);
    HINTERNET hc2 = a_connect(hi, s, NULL, NULL);
    a_send(hc2, &q, &r, 0);
    a_dump(s);
    t_note("same session, new connect handle without creds: status=%lu, %d more requests, first auth=%s", r.status,
           srv_req_count(s) - before, REQ_AUTH(s, before) ? REQ_AUTH(s, before) : "(none)");
    a_close(hc2); t_inet_close(hi); srv_stop(s);
}

TEST(auth_cache_new_session_no_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/s/a"; q.cuser = "user"; q.cpass = "pass"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    int before = srv_req_count(s);
    q.cuser = q.cpass = NULL; a_once(s, &q, &r);
    a_dump(s);
    t_note("new InternetOpen session without creds: status=%lu, %d more requests, first auth=%s", r.status,
           srv_req_count(s) - before, REQ_AUTH(s, before) ? REQ_AUTH(s, before) : "(none)");
    srv_stop(s);
}

TEST(auth_cache_different_creds_on_new_connect) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass"); g.accept[1] = a_basic("user2", "pass2");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pass");
    areq q = {0}; q.path = "/d/a"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    int before = srv_req_count(s);
    HINTERNET hc2 = a_connect(hi, s, "user2", "pass2");
    a_send(hc2, &q, &r, 0);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    const char *last = REQ_AUTH(s, srv_req_count(s) - 1);
    t_note("second connect with other creds: %d more requests, auth seq first=%s last=%s", srv_req_count(s) - before,
           REQ_AUTH(s, before) ? REQ_AUTH(s, before) : "(none)", last ? last : "(none)");
    a_close(hc2); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_cache_not_populated_by_failed_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "right");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "wrong");
    areq q = {0}; q.path = "/f/a"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 401);
    int before = srv_req_count(s);
    HINTERNET hc2 = a_connect(hi, s, NULL, NULL);
    a_send(hc2, &q, &r, 0);
    a_dump(s);
    EXPECT_EQ(r.status, 401);
    t_note("after failed creds, credential-less request: %d more requests, first auth=%s", srv_req_count(s) - before,
           REQ_AUTH(s, before) ? REQ_AUTH(s, before) : "(none)");
    a_close(hc2); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_cache_preemptive_with_no_auth_flag) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pass");
    areq q = {0}; q.path = "/n/a"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    int before = srv_req_count(s);
    q.flags = T_INET_FRESH | INTERNET_FLAG_NO_AUTH; a_send(hc, &q, &r, 0);
    a_dump(s);
    EXPECT_EQ(srv_req_count(s) - before, 1);
    t_note("NO_AUTH after cached creds: status=%lu auth=%s", r.status, REQ_AUTH(s, before) ? REQ_AUTH(s, before) : "(none)");
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_cache_many_sequential_requests) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pass");
    areq q = {0}; q.path = "/m/x"; ares r;
    int ok200 = 0;
    for (int i = 0; i < 10; i++) { a_send(hc, &q, &r, 0); if (r.status == 200) ok200++; }
    EXPECT_EQ(ok200, 10);
    EXPECT_EQ(srv_req_count(s), 11);
    EXPECT_EQ(g.n_deny, 1);
    EXPECT_EQ(n_with_auth(s, 1), 10);
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_cache_realm_change_rechallenges) {
    REQUIRE(U(HttpSendRequestA));
    /* path /r1/ uses realm one; once cached, a server that switches to another realm and creds is retried */
    gate g = {0}; g.challenge = "WWW-Authenticate: Basic realm=\"one\"\r\n"; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pass");
    areq q = {0}; q.path = "/r1/a"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    q.path = "/r1/b"; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 3);
    a_close(hc); t_inet_close(hi); srv_stop(s);
}
