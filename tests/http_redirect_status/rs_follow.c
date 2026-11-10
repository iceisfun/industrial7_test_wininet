/* rs_follow.c - automatic redirect following: status x method matrix, Location forms, drain/connection handling.
 * VM_TIMEOUT: 300
 * Decomp: HTTP_REQUEST_HANDLE_OBJECT::HttpSendRequest_Start@0x72da0 (status switch 300/301/302/303/307/308),
 *         ::Redirect@0x12618 (Location parse, scheme/host checks, header rewrite), ::Redirect_Fsm@0x25064 (drain).
 * See EVIDENCE.md for which expectations are decomp-grounded, VM-observed or knowledge-only. */
#include "rs.h"

/* ------------------------------------------------------------------ status x method matrix */
enum { EXP_SAME, EXP_GET, EXP_CONFIRM };

/* 301/302: POST -> GET, GET/HEAD kept, other methods -> 12168.  303: everything -> GET.
 * 307/308: GET/HEAD kept, every other method -> 12168 (decomp case 0x12d/0x12e, 0x12f, 0x133/0x134). */
static int expected_kind(int code, const char *m) {
    int gethead = !strcmp(m, "GET") || !strcmp(m, "HEAD");
    if (code == 303) return !strcmp(m, "GET") ? EXP_SAME : EXP_GET;
    if (code == 301 || code == 302) {
        if (gethead) return EXP_SAME;
        if (!strcmp(m, "POST")) return EXP_GET;
        return EXP_CONFIRM;
    }
    return gethead ? EXP_SAME : EXP_CONFIRM;
}

static void matrix(int code, const char *m) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", code, "Location: /dst\r\n", "moved-body");
    rs_add(&rt, "/dst", 200, "X-Final: 1\r\n", "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    static const char data[] = "a=1&b=2";
    int has_body = strcmp(m, "GET") && strcmp(m, "HEAD");
    rs_opt o = { 0 };
    o.flags = RS_FRESH;
    o.hdrs = "Content-Type: application/x-www-form-urlencoded\r\nX-Rs: keep\r\n";
    if (has_body) { o.data = data; o.ndata = 7; }
    rs_res r;
    rs_do(s, m, "/src", &o, &r);
    int kind = expected_kind(code, m);
    int nreq = rs_wait(s, kind == EXP_CONFIRM ? 1 : 2, 3000);
    t_note("%d %s -> ok=%d err=%lu(%s) status=%lu url=%s reqs=%d", code, m, r.ok, r.err, rs_err(r.err), r.status, r.url, nreq);
    char want_line[64];
    snprintf(want_line, sizeof want_line, "%s /src HTTP/1.1", m);
    EXPECT_STR(srv_req_line(s, 0), want_line);
    if (has_body) {
        size_t bl = 0; const char *b = srv_req_body(s, 0, &bl);
        CHECK(b && bl == 7 && !memcmp(b, data, 7));
        EXPECT_STR(srv_req_header(s, 0, "Content-Length"), "7");
    }
    if (kind == EXP_CONFIRM) {
        CHECKF(!r.ok, "%d %s should stop for confirmation", code, m);
        EXPECT_EQ(r.err, ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION);
        EXPECT_EQ(nreq, 1);
        EXPECT_EQ(r.status, (DWORD)code);
    } else {
        CHECKF(r.ok, "%d %s err=%lu %s", code, m, r.err, rs_err(r.err));
        EXPECT_EQ(r.status, 200);
        EXPECT_EQ(nreq, 2);
        const char *nm = kind == EXP_GET ? "GET" : m;
        snprintf(want_line, sizeof want_line, "%s /dst HTTP/1.1", nm);
        EXPECT_STR(srv_req_line(s, 1), want_line);
        char url[128]; snprintf(url, sizeof url, "http://%s/dst", rs_hp(s));
        EXPECT_STR(r.url, url);
        EXPECT_STR(srv_req_header(s, 1, "Host"), rs_hp(s));
        EXPECT_STR(srv_req_header(s, 1, "User-Agent"), "rs-agent/1.0");
        EXPECT_STR(srv_req_header(s, 1, "X-Rs"), "keep");          /* caller headers survive the hop */
        if (!strcmp(nm, "HEAD")) EXPECT_EQ(r.nbody, 0); else EXPECT_STR(r.body, "landed");
        if (!strcmp(nm, "GET")) {
            /* Redirect(): new method GET -> RemoveAllRequestHeadersByName(Content-Length=5, Content-Type=1), also GET->GET */
            CHECK(srv_req_header(s, 1, "Content-Length") == NULL);
            CHECK(srv_req_header(s, 1, "Content-Type") == NULL);
            size_t bl = 0; const char *b = srv_req_body(s, 1, &bl);
            CHECK(!b || bl == 0);
        } else if (has_body) {
            size_t bl = 0; const char *b = srv_req_body(s, 1, &bl);
            CHECK(b && bl == 7 && !memcmp(b, data, 7));
        } else {
            EXPECT_STR(srv_req_header(s, 1, "Content-Type"), "application/x-www-form-urlencoded");
        }
        EXPECT_EQ(r.loc_err, ERROR_HTTP_HEADER_NOT_FOUND);       /* final (200) response has no Location */
        EXPECT_STR(r.text, "OK");
    }
    srv_stop(s);
}

#define MX(code, M) TEST(rs_follow_##code##_##M) { matrix(code, #M); }
MX(301, GET) MX(301, HEAD) MX(301, POST) MX(301, PUT) MX(301, DELETE) MX(301, OPTIONS) MX(301, PATCH)
MX(302, GET) MX(302, HEAD) MX(302, POST) MX(302, PUT) MX(302, DELETE) MX(302, OPTIONS) MX(302, PATCH)
MX(303, GET) MX(303, HEAD) MX(303, POST) MX(303, PUT) MX(303, DELETE) MX(303, OPTIONS) MX(303, PATCH)
MX(307, GET) MX(307, HEAD) MX(307, POST) MX(307, PUT) MX(307, DELETE) MX(307, OPTIONS) MX(307, PATCH)
MX(308, GET) MX(308, HEAD) MX(308, POST) MX(308, PUT) MX(308, DELETE) MX(308, OPTIONS) MX(308, PATCH)

/* ------------------------------------------------------------------ 300 / missing Location */
TEST(rs_follow_300_with_location) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 300, "Location: /choice\r\n", "choices");
    rs_add(&rt, "/choice", 200, NULL, "chosen");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    int n = rs_wait(s, 2, 3000);
    t_note("300+Location: ok=%d err=%lu status=%lu reqs=%d body=%s", r.ok, r.err, r.status, n, r.body);
    CHECK(r.ok); EXPECT_EQ(r.status, 200); EXPECT_EQ(n, 2); EXPECT_STR(r.body, "chosen");
    EXPECT_STR(srv_req_line(s, 1), "GET /choice HTTP/1.1");
    srv_stop(s);
}

TEST(rs_follow_300_without_location) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 300, "Content-Type: text/plain\r\n", "pick one");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    int n = rs_wait(s, 1, 2000);
    CHECKF(r.ok, "err=%lu %s", r.err, rs_err(r.err));
    EXPECT_EQ(r.status, 300); EXPECT_EQ(n, 1); EXPECT_STR(r.body, "pick one");
    EXPECT_STR(r.text, "Multiple Choices");
    EXPECT_EQ(r.loc_err, ERROR_HTTP_HEADER_NOT_FOUND);
    srv_stop(s);
}

static void no_location(int code) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", code, "Content-Type: text/plain\r\n", "nowhere");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    Sleep(50);
    int n = srv_req_count(s);
    t_note("%d without Location: ok=%d err=%lu(%s) status=%lu reqs=%d body=%s", code, r.ok, r.err, rs_err(r.err), r.status, n, r.body);
    CHECKF(r.ok, "err=%lu %s", r.err, rs_err(r.err));
    EXPECT_EQ(r.status, (DWORD)code);
    EXPECT_EQ(n, 1);
    EXPECT_STR(r.body, "nowhere");
    char url[128]; snprintf(url, sizeof url, "http://%s/src", rs_hp(s));
    EXPECT_STR(r.url, url);
    srv_stop(s);
}
TEST(rs_follow_301_no_location) { no_location(301); }
TEST(rs_follow_302_no_location) { no_location(302); }
TEST(rs_follow_303_no_location) { no_location(303); }
TEST(rs_follow_307_no_location) { no_location(307); }
TEST(rs_follow_308_no_location) { no_location(308); }

/* 304, 305 and 306 are not in the redirect switch: returned as is (the decomp gate is 300..303, 307, 308). */
static void not_redirect(int code) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", code, "Location: /dst\r\n", code == 304 ? "" : "x");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    Sleep(50);
    int n = srv_req_count(s);
    t_note("%d + Location: ok=%d err=%lu status=%lu reqs=%d", code, r.ok, r.err, r.status, n);
    CHECK(r.ok); EXPECT_EQ(r.status, (DWORD)code); EXPECT_EQ(n, 1);
    char want[256]; snprintf(want, sizeof want, "/dst");
    EXPECT_STR(r.location, want);
    srv_stop(s);
}
TEST(rs_follow_304_not_followed) { not_redirect(304); }
TEST(rs_follow_305_not_followed) { not_redirect(305); }
TEST(rs_follow_306_not_followed) { not_redirect(306); }
TEST(rs_follow_309_not_followed) { not_redirect(309); }
TEST(rs_follow_399_not_followed) { not_redirect(399); }

/* ------------------------------------------------------------------ Location forms */
typedef struct { const char *src; const char *loc; const char *want_target; const char *host_kind; } locform;

static void location_form(const char *src, const char *loc, const char *want_target, const char *want_host /* NULL = 127.0.0.1:P */) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    char hdr[512]; snprintf(hdr, sizeof hdr, "Location: %s\r\n", loc);
    rs_add(&rt, src, 302, hdr, "m");
    rs_add(&rt, "*", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", src, &o, &r);
    int n = rs_wait(s, 2, 3000);
    t_note("Location '%s' from %s -> ok=%d err=%lu status=%lu reqs=%d tgt=%s host=%s url=%s", loc, src, r.ok, r.err, r.status, n,
           srv_req_target(s, 1) ? srv_req_target(s, 1) : "-", srv_req_header(s, 1, "Host") ? srv_req_header(s, 1, "Host") : "-", r.url);
    CHECKF(r.ok, "err=%lu %s", r.err, rs_err(r.err));
    EXPECT_EQ(r.status, 200); EXPECT_EQ(n, 2);
    EXPECT_STR(srv_req_target(s, 1), want_target);
    char host[128];
    if (want_host) snprintf(host, sizeof host, want_host, srv_port(s)); else snprintf(host, sizeof host, "%s", rs_hp(s));
    EXPECT_STR(srv_req_header(s, 1, "Host"), host);
    char url[512]; snprintf(url, sizeof url, "http://%s%s", host, want_target);
    EXPECT_STR(r.url, url);
    EXPECT_STR(r.body, "landed");
    srv_stop(s);
}
TEST(rs_loc_absolute_same_host)  { location_form("/src", "http://127.0.0.1:%P/abs", "/abs", NULL); }
TEST(rs_loc_absolute_localhost)  { location_form("/src", "http://localhost:%P/lh", "/lh", "localhost:%u"); }
TEST(rs_loc_absolute_ipv6)       { location_form("/src", "http://[::1]:%P/v6", "/v6", "[::1]:%u"); }
TEST(rs_loc_protocol_relative)   { location_form("/src", "//127.0.0.1:%P/pr", "/pr", NULL); }
TEST(rs_loc_relative_no_slash)   { location_form("/dir/src", "sib", "/dir/sib", NULL); }
TEST(rs_loc_relative_dotdot)     { location_form("/a/b/src", "../up", "/a/up", NULL); }
TEST(rs_loc_relative_dot)        { location_form("/a/b/src", "./here", "/a/b/here", NULL); }
TEST(rs_loc_relative_query_only) { location_form("/q/src", "?k=v", "/q/src?k=v", NULL); }
TEST(rs_loc_with_query)          { location_form("/src", "/dst?x=1&y=two", "/dst?x=1&y=two", NULL); }
TEST(rs_loc_fragment_stripped)   { location_form("/src", "/frag#section", "/frag", NULL); }
TEST(rs_loc_abs_fragment)        { location_form("/src", "http://127.0.0.1:%P/af?q=1#f", "/af?q=1", NULL); }
TEST(rs_loc_uppercase_scheme)    { location_form("/src", "HTTP://127.0.0.1:%P/up", "/up", NULL); }
TEST(rs_loc_no_path)             { location_form("/src", "http://127.0.0.1:%P", "/", NULL); }
TEST(rs_loc_padded_whitespace)   { location_form("/src", "   /ws   ", "/ws", NULL); }
TEST(rs_loc_root)                { location_form("/deep/er/src", "/", "/", NULL); }
TEST(rs_loc_query_from_query)    { location_form("/src?a=1", "/dst?b=2", "/dst?b=2", NULL); }
TEST(rs_loc_same_path)           { location_form("/src", "/src?again=1", "/src?again=1", NULL); }
TEST(rs_loc_encoded_chars)       { location_form("/src", "/p%20q", "/p%20q", NULL); }
TEST(rs_loc_double_slash_path)   { location_form("/src", "/x//y", "/x//y", NULL); }

/* the header name is case-insensitive */
TEST(rs_loc_header_name_case) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "LOCATION: /upper\r\n", "m");
    rs_add(&rt, "/upper", 200, NULL, "ok");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 200); EXPECT_EQ(rs_wait(s, 2, 3000), 2);
    EXPECT_STR(srv_req_target(s, 1), "/upper");
    srv_stop(s);
}

/* two Location headers: the first one is used (Redirect() reads index 0 of header 0x21) */
TEST(rs_loc_two_headers_first_wins) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /first\r\nLocation: /second\r\n", "m");
    rs_add(&rt, "*", 200, NULL, "ok");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(rs_wait(s, 2, 3000), 2);
    EXPECT_STR(srv_req_target(s, 1), "/first");
    srv_stop(s);
}

/* redirect to a different port (second server) */
TEST(rs_loc_other_port) {
    REQUIRE(U(HttpSendRequestA));
    rs_router r2; rs_router_init(&r2);
    rs_add(&r2, "/there", 200, NULL, "other-server");
    srv *s2; RS_START(&r2, SRV_HTTP, s2);
    rs_router rt; rs_router_init(&rt); rt.alt_port = srv_port(s2);
    rs_add(&rt, "/src", 302, "Location: http://127.0.0.1:%A/there\r\n", "m");
    srv *s = rs_start(&rt, SRV_HTTP);
    if (!s) { srv_stop(s2); t_skip("server unavailable"); return; }
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "other-server");
    EXPECT_EQ(rs_wait(s, 1, 2000), 1);
    EXPECT_EQ(rs_wait(s2, 1, 2000), 1);
    EXPECT_STR(srv_req_line(s2, 0), "GET /there HTTP/1.1");
    EXPECT_STR(srv_req_header(s2, 0, "Host"), rs_hp(s2));
    char url[128]; snprintf(url, sizeof url, "http://%s/there", rs_hp(s2));
    EXPECT_STR(r.url, url);
    srv_stop(s); srv_stop(s2);
}

/* hop through two other ports and back */
TEST(rs_loc_port_ping_pong) {
    REQUIRE(U(HttpSendRequestA));
    rs_router r2; rs_router_init(&r2);
    srv *s2; RS_START(&r2, SRV_HTTP, s2);
    rs_router rt; rs_router_init(&rt); rt.alt_port = srv_port(s2);
    srv *s = rs_start(&rt, SRV_HTTP);
    if (!s) { srv_stop(s2); t_skip("server unavailable"); return; }
    r2.alt_port = srv_port(s);
    rs_add(&rt, "/a", 302, "Location: http://127.0.0.1:%A/b\r\n", "");
    rs_add(&r2, "/b", 302, "Location: http://127.0.0.1:%A/c\r\n", "");
    rs_add(&rt, "/c", 200, NULL, "home");
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/a", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "home");
    EXPECT_EQ(rs_wait(s, 2, 2000), 2); EXPECT_EQ(rs_wait(s2, 1, 2000), 1);
    EXPECT_STR(srv_req_target(s, 1), "/c");
    char url[128]; snprintf(url, sizeof url, "http://%s/c", rs_hp(s));
    EXPECT_STR(r.url, url);
    srv_stop(s); srv_stop(s2);
}

/* InternetConnect to "localhost", redirect to 127.0.0.1: Host header follows the new authority */
TEST(rs_loc_host_change_from_localhost) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: http://127.0.0.1:%P/ip\r\n", "");
    rs_add(&rt, "/ip", 200, NULL, "ip");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.host = "localhost"; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(rs_wait(s, 2, 3000), 2);
    char lh[64]; snprintf(lh, sizeof lh, "localhost:%u", srv_port(s));
    EXPECT_STR(srv_req_header(s, 0, "Host"), lh);
    EXPECT_STR(srv_req_header(s, 1, "Host"), rs_hp(s));
    t_note("conn of req0=%d req1=%d", srv_req_conn(s, 0), srv_req_conn(s, 1));
    srv_stop(s);
}

/* ------------------------------------------------------------------ chains, drain and connections */
static void chain(int hops) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    char *last = malloc(32); snprintf(last, 32, "/loop/%d", hops);
    rs_add(&rt, last, 200, NULL, "end");
    rs_add(&rt, "/loop/*", 302, "Location: /loop/%N\r\n", "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/loop/0", &o, &r);
    int n = rs_wait(s, hops + 1, 5000);
    CHECKF(r.ok, "hops=%d err=%lu %s", hops, r.err, rs_err(r.err));
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "end"); EXPECT_EQ(n, hops + 1);
    char url[128]; snprintf(url, sizeof url, "http://%s%s", rs_hp(s), last);
    EXPECT_STR(r.url, url);
    for (int i = 0; i <= hops && i < n; i++) {
        char t[32]; snprintf(t, sizeof t, "/loop/%d", i);
        EXPECT_STR(srv_req_target(s, i), t);
    }
    EXPECT_EQ(srv_conn_count(s), 1);   /* every 302 had an empty Content-Length body: one keep-alive connection */
    srv_stop(s); free(last);
}
TEST(rs_chain_2) { chain(2); }
TEST(rs_chain_5) { chain(5); }
TEST(rs_chain_10) { chain(10); }
TEST(rs_chain_20) { chain(20); }

static void drain_case(unsigned flags, int big, int want_conns /* -1 = note only */) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_route *e = rs_addx(&rt, "/src", 302, "Location: /dst\r\n", "redirect body text", flags);
    if (big) { e->flags |= RS_F_BIGBODY; e->code2 = big; }
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    int n = rs_wait(s, 2, 3000);
    t_note("drain flags=0x%x big=%d: ok=%d status=%lu reqs=%d conns=%d", flags, big, r.ok, r.status, n, srv_conn_count(s));
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "landed"); EXPECT_EQ(n, 2);
    if (want_conns >= 0) EXPECT_EQ(srv_conn_count(s), want_conns);
    srv_stop(s);
}
TEST(rs_drain_small_body_keepalive)  { drain_case(0, 0, 1); }
TEST(rs_drain_chunked_body)          { drain_case(RS_F_CHUNKED, 0, 1); }
TEST(rs_drain_64k_body)              { drain_case(0, 65536, -1); }
TEST(rs_drain_300k_body)             { drain_case(0, 300000, -1); }
TEST(rs_drain_connection_close)      { drain_case(RS_F_CLOSE, 0, 2); }
TEST(rs_drain_close_delimited)       { drain_case(RS_F_NOLEN, 0, 2); }
TEST(rs_drain_http10)                { drain_case(RS_F_HTTP10, 0, -1); }

/* the 3xx body is never handed to the caller when the redirect is followed */
TEST(rs_follow_body_is_target_body) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 301, "Location: /dst\r\nContent-Type: text/html\r\n", "<html>moved</html>");
    rs_add(&rt, "/dst", 200, "Content-Type: text/plain\r\n", "target");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_STR(r.body, "target"); EXPECT_EQ(r.nbody, 6);
    CHECK(strstr(r.raw, "HTTP/1.1 200 OK\r\n") == r.raw);
    CHECK(strstr(r.raw, "Location") == NULL);
    CHECK(strstr(r.raw, "text/plain") != NULL);
    char ct[64]; DWORD l = sizeof ct;
    CHECK(U(HttpQueryInfoA) != NULL);
    srv_stop(s);
}

/* InternetOpenUrl follows by default and reports the final URL */
TEST(rs_openurl_follows) {
    REQUIRE(U(InternetOpenUrlA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/src"), NULL, 0, RS_FRESH, 0);
    CHECKF(hu != NULL, "err=%lu", GetLastError());
    if (hu) {
        rs_res r; memset(&r, 0, sizeof r); rs_collect(hu, &r, 1);
        EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "landed");
        EXPECT_STR(r.url, srv_url(s, "/dst"));
        U(InternetCloseHandle)(hu);
    }
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    t_inet_close(hi); srv_stop(s);
}

TEST(rs_openurl_no_auto_redirect) {
    REQUIRE(U(InternetOpenUrlA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "moved");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/src"), NULL, 0, RS_NOREDIR, 0);
    CHECKF(hu != NULL, "err=%lu", GetLastError());
    if (hu) {
        rs_res r; memset(&r, 0, sizeof r); rs_collect(hu, &r, 1);
        EXPECT_EQ(r.status, 302); EXPECT_STR(r.body, "moved"); EXPECT_STR(r.location, "/dst");
        EXPECT_STR(r.url, srv_url(s, "/src"));
        U(InternetCloseHandle)(hu);
    }
    Sleep(50);
    EXPECT_EQ(srv_req_count(s), 1);
    t_inet_close(hi); srv_stop(s);
}
