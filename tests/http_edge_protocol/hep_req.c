/* hep_req.c - what the client puts on the wire for unusual request parameters: method tokens and their case, NULL
 * verb/object/version, odd versions, header-length arguments, CR/LF injection through every input (verb, object,
 * version, headers, added headers, user agent, referrer), A vs W header conversion of non-ASCII text,
 * HttpAddRequestHeaders on a request that was already sent.
 * Code-page facts: HttpOpenRequestW verb/version ACP-then-UTF-8, object UTF-8; HttpAddRequestHeadersW UTF-8
 * (docs/research/02 0.1, decomp HttpOpenRequestW@0xbea10 / HttpAddRequestHeadersW@0x88860). Wire bytes are Win10 VM
 * observations (EVIDENCE.md). */
#include "hep.h"
#include <stdlib.h>

/* open + send one request with the given parameters to a default server; returns 1 if the server recorded it */
typedef struct { BOOL open_ok; DWORD open_err; BOOL ok; DWORD err; int status; } rq_out;
static int one(hep_srv *h, const char *verb, const char *obj, const char *ver, const char *hdrs, DWORD hlen, const void *opt, DWORD optlen, rq_out *o) {
    memset(o, 0, sizeof *o);
    HINTERNET hi = hep_session("hep-req", 3000), hc = hep_connect(hi, h);
    SetLastError(0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, verb, obj, ver, NULL, NULL, HEP_F, 0);
    o->open_ok = hr != NULL; o->open_err = hr ? 0 : GetLastError();
    if (hr) {
        SetLastError(0);
        o->ok = U(HttpSendRequestA)(hr, hdrs, hlen, (LPVOID)opt, optlen);
        o->err = o->ok ? 0 : GetLastError();
        if (o->ok) { DWORD st = 0, l = sizeof st; U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL); o->status = (int)st;
                     char b[64]; t_inet_read_all(hr, b, sizeof b, NULL); }
        U(InternetCloseHandle)(hr);
    }
    U(InternetCloseHandle)(hc); t_inet_close(hi);
    return o->ok ? srv_wait_requests(h->s, 1, 2000) : 0;
}
static const char *wire_sig(hep_srv *h, const rq_out *o) {
    static char b[4][3000]; static volatile LONG k; char *s = b[InterlockedIncrement(&k) & 3];
    if (!o->open_ok) { snprintf(s, 3000, "open=0 err=%lu", o->open_err); return s; }
    if (!o->ok) { snprintf(s, 3000, "send=0 err=%lu reqs=%d", o->err, srv_req_count(h->s)); return s; }
    snprintf(s, 3000, "st=%d line=%s hdrs=%s", o->status, hep_esc(srv_req_line(h->s, 0), strlen(srv_req_line(h->s, 0) ? srv_req_line(h->s, 0) : "")), hep_names(h->s, 0));
    return s;
}

/* ------------------------------------------------------------ method tokens */
typedef struct { const char *verb; const char *want_line_prefix; } verb_case;
static const verb_case verbs[] = {
    { "GET", "GET /m HTTP/1.1" }, { "get", NULL }, { "Get", NULL }, { "gEt", NULL },
    { "POST", "POST /m HTTP/1.1" }, { "post", NULL }, { "HEAD", "HEAD /m HTTP/1.1" }, { "head", NULL },
    { "PUT", "PUT /m HTTP/1.1" }, { "put", NULL }, { "DELETE", "DELETE /m HTTP/1.1" }, { "delete", NULL },
    { "OPTIONS", "OPTIONS /m HTTP/1.1" }, { "CONNECT", NULL }, { "PATCH", "PATCH /m HTTP/1.1" },
    { "PROPFIND", NULL }, { "MKCOL", NULL }, { "M-SEARCH", NULL }, { "FOO", NULL }, { "foo_bar", NULL }, { "X", NULL },
    { "VERYLONGMETHODNAMEVERYLONGMETHODNAMEVERYLONGMETHODNAMEVERYLONGMETHODNAME", NULL },
};
GTEST(hep_method_token_table, 60000) {
    HEP_REQUIRE_HTTP();
    for (size_t i = 0; i < sizeof verbs / sizeof verbs[0]; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        rq_out o; one(h, verbs[i].verb, "/m", NULL, NULL, 0, NULL, 0, &o);
        const char *sig = wire_sig(h, &o);
        t_note("OBS verb [%s] -> %s", verbs[i].verb, sig);
        CHECKF(o.ok, "verb %s err %lu", verbs[i].verb, o.err);
        if (o.ok && srv_req_count(h->s) > 0) {
            /* the method is sent exactly as given (no case folding) */
            EXPECT_STR(srv_req_method(h->s, 0), verbs[i].verb);
            if (verbs[i].want_line_prefix) EXPECT_STR(srv_req_line(h->s, 0), verbs[i].want_line_prefix);
        }
        hep_stop(h);
    }
}
GTEST(hep_method_trace_track_rejected, 60000) {
    /* decomp InternalHttpOpenRequestA@0x8b9b0: verb compared with CompareStringA(NORM_IGNORECASE) against "TRACE" and
     * "TRACK" -> 0x2ef0 = 12016 ERROR_INTERNET_INVALID_OPERATION, no handle */
    HEP_REQUIRE_HTTP();
    static const char *vs[] = { "TRACE", "trace", "Trace", "TRACK", "track", "tRaCk" };
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    for (int i = 0; i < 6; i++) {
        SetLastError(0);
        HINTERNET hr = U(HttpOpenRequestA)(hc, vs[i], "/t", NULL, NULL, NULL, HEP_F, 0);
        CHECKF(hr == NULL, "%s accepted", vs[i]);
        EXPECT_ERR(ERROR_INTERNET_INVALID_OPERATION);
        if (hr) U(InternetCloseHandle)(hr);
    }
    /* near misses are ordinary methods */
    static const char *ok[] = { "TRACES", "TRAC", "XTRACE" };
    for (int i = 0; i < 3; i++) {
        HINTERNET hr = U(HttpOpenRequestA)(hc, ok[i], "/t", NULL, NULL, NULL, HEP_F, 0);
        CHECKF(hr != NULL, "%s rejected err %lu", ok[i], GetLastError());
        if (hr) U(InternetCloseHandle)(hr);
    }
    U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_method_trace_rejected_w, 60000) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    SetLastError(0);
    HINTERNET hr = U(HttpOpenRequestW)(hc, L"trace", L"/t", NULL, NULL, NULL, HEP_F, 0);
    CHECK(hr == NULL);
    EXPECT_ERR(ERROR_INTERNET_INVALID_OPERATION);
    if (hr) U(InternetCloseHandle)(hr);
    U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_method_lowercase_head_reads_body, 60000) {
    /* "head" in lower case: is it treated as HEAD (no body expected) or as an unknown method that has a body? */
    HEP_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"), S_CLOSE() };
    static const char *vs[] = { "HEAD", "head", "Head" };
    for (int i = 0; i < 3; i++) {
        HEP_SRV(h, hep_start(st, 3));
        hep_req rq = {0}; hep_res r; rq.verb = vs[i];
        hep_do(h, &rq, &r);
        t_note("OBS verb %s on CL:4 reply -> %s", vs[i], hep_sig(&r, 0));
        CHECK(r.ok);
        if (i == 0) EXPECT_EQ(r.nbody, 0);
        hep_stop(h);
    }
}
GTEST(hep_method_null_is_get, 60000) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    rq_out o; CHECK(one(h, NULL, "/n", NULL, NULL, 0, NULL, 0, &o));
    EXPECT_STR(srv_req_line(h->s, 0), "GET /n HTTP/1.1");
    hep_stop(h);
}
GTEST(hep_method_empty_string, 60000) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    rq_out o; one(h, "", "/n", NULL, NULL, 0, NULL, 0, &o);
    t_note("OBS empty verb -> %s", wire_sig(h, &o));
    hep_stop(h);
}
GTEST(hep_method_with_space_and_ctl, 60000) {
    HEP_REQUIRE_HTTP();
    static const char *vs[] = { "GE T", "GET ", " GET", "G\tET", "GET\r\nX-Inj: 1\r\n", "GET /evil HTTP/1.1\r\nX:", "G\x80T", "G\xc3\xa9T" };
    for (size_t i = 0; i < sizeof vs / sizeof vs[0]; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        rq_out o; one(h, vs[i], "/v", NULL, NULL, 0, NULL, 0, &o);
        t_note("OBS verb [%s] -> %s raw=%s", hep_esc(vs[i], strlen(vs[i])), wire_sig(h, &o), o.ok ? hep_raw(h->s, 0) : "-");
        hep_stop(h);
    }
}

/* ------------------------------------------------------------ object (request target) */
typedef struct { const char *obj; const char *want_target; } obj_case;
static const obj_case objs[] = {
    { NULL, "/" }, { "", NULL }, { "/", "/" }, { "x", NULL }, { "x/y", NULL }, { "*", NULL }, { "//double", NULL },
    { "/a/../b", NULL }, { "/a/./b", NULL }, { "/a b", NULL }, { "/a%20b", "/a%20b" }, { "/a+b", "/a+b" },
    { "/%41%42", NULL }, { "/%zz", NULL }, { "/%", NULL }, { "/%2", NULL }, { "/%00x", NULL }, { "/%2F", NULL },
    { "/p?q=1&r=2", "/p?q=1&r=2" }, { "/p?q=a b", NULL }, { "/p?", NULL }, { "/p#frag", NULL }, { "/p?q#f", NULL },
    { "/back\\slash", NULL }, { "/tab\there", NULL }, { "/quote\"x", NULL }, { "/lt<gt>", NULL }, { "/brace{}|^`", NULL },
    { "/\x7f", NULL }, { "/\xe9", NULL }, { "/\xc3\xa9", NULL }, { "/\xe4\xb8\xad", NULL },
    { "http://other.example/abs", NULL }, { "http://127.0.0.1/abs", NULL }, { "HTTP://X/Y", NULL }, { "ftp://x/y", NULL },
    { "/crlf\r\nX-Inj: 1", NULL }, { "/lf\nX-Inj: 1", NULL }, { "/cr\rX", NULL },
    { "/space HTTP/1.0\r\nX-Inj: 1\r\n\r\nGET /smuggled", NULL },
};
GTEST(hep_object_table, 60000) {
    HEP_REQUIRE_HTTP();
    for (size_t i = 0; i < sizeof objs / sizeof objs[0]; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        rq_out o; one(h, "GET", objs[i].obj, NULL, NULL, 0, NULL, 0, &o);
        const char *nm = objs[i].obj ? hep_esc(objs[i].obj, strlen(objs[i].obj)) : "(null)";
        t_note("OBS obj [%s] -> %s | %s", nm, o.ok ? hep_esc(srv_req_target(h->s, 0) ? srv_req_target(h->s, 0) : "", srv_req_target(h->s, 0) ? strlen(srv_req_target(h->s, 0)) : 0) : "-",
               o.ok ? hep_raw(h->s, 0) : wire_sig(h, &o));
        if (objs[i].want_target) { CHECK(o.ok); if (o.ok) EXPECT_STR(srv_req_target(h->s, 0), objs[i].want_target); }
        hep_stop(h);
    }
}

/* ------------------------------------------------------------ version */
typedef struct { const char *ver; const char *want_line; } ver_case;
static const ver_case vers[] = {
    { NULL, "GET /v HTTP/1.1" }, { "HTTP/1.1", "GET /v HTTP/1.1" }, { "HTTP/1.0", NULL }, { "", NULL }, { "HTTP/2.0", NULL },
    { "HTTP/0.9", NULL }, { "http/1.1", NULL }, { "FOO/9", NULL }, { "HTTP/1.1\r\nX-Inj: 1", NULL }, { "HTTP/1.1 extra", NULL },
};
GTEST(hep_version_table, 60000) {
    HEP_REQUIRE_HTTP();
    for (size_t i = 0; i < sizeof vers / sizeof vers[0]; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        rq_out o; one(h, "GET", "/v", vers[i].ver, NULL, 0, NULL, 0, &o);
        t_note("OBS version [%s] -> %s raw=%s", vers[i].ver ? hep_esc(vers[i].ver, strlen(vers[i].ver)) : "(null)", wire_sig(h, &o), o.ok ? hep_raw(h->s, 0) : "-");
        if (vers[i].want_line) { CHECK(o.ok); if (o.ok) EXPECT_STR(srv_req_line(h->s, 0), vers[i].want_line); }
        hep_stop(h);
    }
}
GTEST(hep_all_null_open_request, 60000) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, NULL, NULL, NULL, NULL, NULL, HEP_F, 0);
    CHECK(hr != NULL);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    CHECK(srv_wait_requests(h->s, 1, 2000));
    EXPECT_STR(srv_req_line(h->s, 0), "GET / HTTP/1.1");
    /* the request line queries agree */
    char b[64]; DWORD l = sizeof b;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_REQUEST_METHOD, b, &l, NULL)); EXPECT_STR(b, "GET");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_all_null_open_request_w, 60000) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpSendRequestW));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestW)(hc, NULL, NULL, NULL, NULL, NULL, HEP_F, 0);
    CHECK(hr != NULL);
    CHECK(U(HttpSendRequestW)(hr, NULL, 0, NULL, 0));
    CHECK(srv_wait_requests(h->s, 1, 2000));
    EXPECT_STR(srv_req_line(h->s, 0), "GET / HTTP/1.1");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}

/* ------------------------------------------------------------ HttpSendRequest header length */
typedef struct { const char *hdrs; DWORD len; const char *tag; } hlen_case;
static const char H3[] = "X-A: 1\r\nX-B: 2\r\nX-C: 3\r\n";   /* 24 bytes */
static const hlen_case hlens[] = {
    { H3, (DWORD)-1, "minus1" }, { H3, 24, "exact" }, { H3, 22, "minus_crlf" }, { H3, 16, "two_lines" }, { H3, 14, "cut_after_value_2" },
    { H3, 12, "cut_in_value_2" }, { H3, 10, "cut_in_name_2" }, { H3, 8, "one_line" }, { H3, 6, "cut_before_crlf" }, { H3, 3, "cut_in_name" },
    { H3, 1, "one_char" }, { H3, 25, "plus_nul" }, { H3, 0, "zero" }, { "X-A: 1", (DWORD)-2, "minus2" },
    { "X-A: 1\0X-B: 2\r\n", 15, "embedded_nul" }, { "X-A: 1\r\n\r\nX-B: 2\r\n", (DWORD)-1, "blank_line_middle" },
    { "\r\n\r\nX-A: 1\r\n", (DWORD)-1, "leading_blank_lines" }, { "X-A: 1\nX-B: 2\n", (DWORD)-1, "lf_only" },
    { "X-A: 1\rX-B: 2\r", (DWORD)-1, "cr_only" }, { "X-A: 1", (DWORD)-1, "no_crlf" },
};
GTEST(hep_send_header_length_table, 60000) {
    HEP_REQUIRE_HTTP();
    for (size_t i = 0; i < sizeof hlens / sizeof hlens[0]; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        rq_out o; one(h, "GET", "/h", NULL, hlens[i].hdrs, hlens[i].len, NULL, 0, &o);
        t_note("OBS hlen %s (%ld) -> %s", hlens[i].tag, (long)hlens[i].len, wire_sig(h, &o));
        if (o.ok) t_note("OBS hlen %s raw=%s", hlens[i].tag, hep_raw(h->s, 0));
        hep_stop(h);
    }
}
GTEST(hep_send_header_length_exact_and_minus1_agree, 60000) {
    HEP_REQUIRE_HTTP();
    hep_srv *h1 = hep_start_ok(); if (!h1) return;
    hep_srv *h2 = hep_start_ok(); if (!h2) { hep_stop(h1); return; }
    rq_out o1, o2;
    CHECK(one(h1, "GET", "/h", NULL, H3, (DWORD)-1, NULL, 0, &o1));
    CHECK(one(h2, "GET", "/h", NULL, H3, 24, NULL, 0, &o2));
    EXPECT_STR(hep_names(h1->s, 0), hep_names(h2->s, 0));
    EXPECT_HDR(h1->s, 0, "X-C", "3"); EXPECT_HDR(h2->s, 0, "X-C", "3");
    hep_stop(h1); hep_stop(h2);
}
GTEST(hep_send_header_length_two_lines_prefix, 60000) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    rq_out o; CHECK(one(h, "GET", "/h", NULL, H3, 16, NULL, 0, &o));
    EXPECT_HDR(h->s, 0, "X-A", "1"); EXPECT_HDR(h->s, 0, "X-B", "2"); EXPECT_NOHDR(h->s, 0, "X-C");
    hep_stop(h);
}
GTEST(hep_send_header_length_w_table, 60000) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpSendRequestW));
    static const WCHAR hw[] = L"X-A: 1\r\nX-B: 2\r\nX-C: 3\r\n";
    static const DWORD lens[] = { (DWORD)-1, 24, 16, 8, 0, 48, 25 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
        HINTERNET hr = U(HttpOpenRequestW)(hc, L"GET", L"/w", NULL, NULL, NULL, HEP_F, 0);
        SetLastError(0);
        BOOL ok = U(HttpSendRequestW)(hr, hw, lens[i], NULL, 0);
        DWORD e = ok ? 0 : GetLastError();
        if (ok) { char b[16]; t_inet_read_all(hr, b, sizeof b, NULL); srv_wait_requests(h->s, 1, 2000); }
        t_note("OBS W hlen %ld -> ok=%d err=%lu names=%s", (long)lens[i], ok, e, ok ? hep_names(h->s, 0) : "-");
        U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
    }
}

/* ------------------------------------------------------------ CR/LF injection */
typedef struct { const char *add; DWORD flags; const char *tag; } inj_case;
static const inj_case injs[] = {
    { "X-A: v\r\nX-Inj: 1", HTTP_ADDREQ_FLAG_ADD, "crlf_two_headers" },
    { "X-A: a\rb", HTTP_ADDREQ_FLAG_ADD, "bare_cr_in_value" },
    { "X-A: a\nX-Inj: 1", HTTP_ADDREQ_FLAG_ADD, "bare_lf_in_value" },
    { "X-A: v\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x", HTTP_ADDREQ_FLAG_ADD, "double_crlf_smuggle" },
    { "X-A: v\r\n X-Fold: 1", HTTP_ADDREQ_FLAG_ADD, "obs_fold" },
    { "X-A: a\0X-Inj: 1", HTTP_ADDREQ_FLAG_ADD, "nul_in_value" },
    { "X-A: v\r\nHost: evil.example", HTTP_ADDREQ_FLAG_ADD, "host_override" },
    { "X-A: v\r\nContent-Length: 999", HTTP_ADDREQ_FLAG_ADD, "content_length_inject" },
    { "X-A: v\r\nTransfer-Encoding: chunked", HTTP_ADDREQ_FLAG_ADD, "te_inject" },
    { "X-A: v\r\n", HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD, "replace_add_crlf" },
    { "X-A: \x80\xff", HTTP_ADDREQ_FLAG_ADD, "high_bytes" },
    { "X-A: \t v \t", HTTP_ADDREQ_FLAG_ADD, "ws_value" },
};
GTEST(hep_inject_add_request_headers_table, 60000) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpAddRequestHeadersA));
    for (size_t i = 0; i < sizeof injs / sizeof injs[0]; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/i", NULL, NULL, NULL, HEP_F, 0);
        SetLastError(0);
        BOOL add = U(HttpAddRequestHeadersA)(hr, injs[i].add, (DWORD)-1, injs[i].flags);
        DWORD ae = add ? 0 : GetLastError();
        BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
        DWORD se = ok ? 0 : GetLastError();
        if (ok) { char b[16]; t_inet_read_all(hr, b, sizeof b, NULL); }
        int got = srv_wait_requests(h->s, 1, 2000);
        t_note("OBS inject add %s -> add=%d/%lu send=%d/%lu reqs=%d raw=%s", injs[i].tag, add, ae, ok, se, srv_req_count(h->s), got ? hep_raw(h->s, 0) : "-");
        /* whatever happens, only one request may reach the server */
        Sleep(50);
        EXPECT_EQ(srv_req_count(h->s) <= 1, 1);
        U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
    }
}
GTEST(hep_inject_crlf_in_add_gives_two_headers, 60000) {
    /* documented: lpszHeaders may hold several CRLF-separated headers */
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpAddRequestHeadersA));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/i", NULL, NULL, NULL, HEP_F, 0);
    CHECK(U(HttpAddRequestHeadersA)(hr, "X-A: v\r\nX-Inj: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    CHECK(srv_wait_requests(h->s, 1, 2000));
    EXPECT_HDR(h->s, 0, "X-A", "v"); EXPECT_HDR(h->s, 0, "X-Inj", "1");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
/* HttpSendRequestA lpszHeaders with embedded line breaks. want_err != 0: the send fails before anything reaches the
 * wire; else want_names is the header-name list the server saw. Win10 VM. */
typedef struct { const char *hdrs; DWORD want_err; const char *want_names; } send_inj;
static const send_inj send_injs[] = {
    { "X-A: v\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n", ERROR_HTTP_HEADER_NOT_FOUND, NULL },   /* blank line in the middle */
    { "X-A: a\rb\r\n", ERROR_HTTP_HEADER_NOT_FOUND, NULL },                                               /* bare CR */
    { "X-A: a\nX-Inj: 1\r\n", 0, "X-A|X-Inj|User-Agent|Host|Connection|Cache-Control" },                  /* bare LF splits */
    { "X-A: v\r\nHost: evil.example\r\n", 0, "X-A|Host|User-Agent|Connection|Cache-Control" },           /* Host replaced */
    { "X-A: v\r\n X-Fold: 1\r\n", 0, "X-A|X-Fold|User-Agent|Host|Connection|Cache-Control" },             /* no folding */
    { "X-A: v\r\nUser-Agent: other\r\n", 0, NULL },
};
GTEST(hep_inject_send_headers_table, 60000) {
    HEP_REQUIRE_HTTP();
    for (size_t i = 0; i < sizeof send_injs / sizeof send_injs[0]; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        const char *hd = send_injs[i].hdrs;
        rq_out o; one(h, "GET", "/s", NULL, hd, (DWORD)-1, NULL, 0, &o);
        Sleep(50);
        t_note("OBS inject send [%s] -> %s reqs=%d raw=%s", hep_esc(hd, strlen(hd)), wire_sig(h, &o), srv_req_count(h->s), o.ok ? hep_raw(h->s, 0) : "-");
        EXPECT_EQ(srv_req_count(h->s) <= 1, 1);
        if (send_injs[i].want_err) { CHECK(!o.ok); EXPECT_EQ(o.err, send_injs[i].want_err); EXPECT_EQ(srv_req_count(h->s), 0); }
        else {
            CHECKF(o.ok, "[%s] err %lu", hep_esc(hd, strlen(hd)), o.err);
            if (o.ok && send_injs[i].want_names) EXPECT_STR(hep_names(h->s, 0), send_injs[i].want_names);
        }
        hep_stop(h);
    }
}
GTEST(hep_inject_send_headers_split_values, 30000) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    rq_out o;
    CHECK(one(h, "GET", "/s", NULL, "X-A: a\nX-Inj: 1\r\nX-B: v\r\n X-Fold: 1\r\nX-C: w\r\nHost: evil.example\r\n", (DWORD)-1, NULL, 0, &o));
    if (srv_req_count(h->s)) {
        EXPECT_HDR(h->s, 0, "X-A", "a"); EXPECT_HDR(h->s, 0, "X-Inj", "1"); EXPECT_HDR(h->s, 0, "X-B", "v");
        EXPECT_HDR(h->s, 0, "X-Fold", "1"); EXPECT_HDR(h->s, 0, "Host", "evil.example");
        EXPECT_EQ(srv_req_header_occurrences(h->s, 0, "Host"), 1);
    }
    hep_stop(h);
}
GTEST(hep_inject_send_content_length_header, 30000) {
    /* a caller-supplied Content-Length with no body goes out verbatim (the server must not wait for it here) */
    HEP_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "ok"), S_CLOSE() };
    HEP_SRV(h, hep_start(st, 3));
    rq_out o; one(h, "GET", "/s", NULL, "X-A: v\r\nContent-Length: 5\r\n", (DWORD)-1, NULL, 0, &o);
    t_note("OBS caller Content-Length 5 without body -> %s", wire_sig(h, &o));
    if (srv_wait_requests(h->s, 1, 2000)) EXPECT_HDR(h->s, 0, "Content-Length", "5");
    hep_stop(h);
}
GTEST(hep_inject_send_connection_close_header, 30000) {
    /* first VM boot: this case did not return within 400 s (sync HttpSendRequest + "X-A: v\r\nConnection: close") */
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session("hep-cc", 3000), hc = hep_connect(hi, h);
    t_note("step open");
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/s", NULL, NULL, NULL, HEP_F, 0);
    t_note("step send");
    BOOL ok = U(HttpSendRequestA)(hr, "X-A: v\r\nConnection: close\r\n", (DWORD)-1, NULL, 0);
    t_note("step sent ok=%d err=%lu", ok, ok ? 0 : GetLastError());
    if (ok) { char b[16]; int rok; size_t n = t_inet_read_all(hr, b, sizeof b, &rok); t_note("step read n=%zu ok=%d", n, rok); }
    if (srv_wait_requests(h->s, 1, 2000)) t_note("OBS Connection: close via send headers raw=%s", hep_raw(h->s, 0));
    U(InternetCloseHandle)(hr); t_note("step closed request");
    U(InternetCloseHandle)(hc); t_inet_close(hi); t_note("step closed session");
    hep_stop(h); t_note("step server stopped");
}
GTEST(hep_inject_user_agent_crlf, 60000) {
    HEP_REQUIRE_HTTP();
    static const char *agents[] = { "ua\r\nX-Inj: 1", "ua\nX-Inj: 1", "ua\rX", "ua\r\n\r\nGET /smuggled HTTP/1.1" };
    for (int i = 0; i < 4; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        hep_req rq = {0}; hep_res r; rq.agent = agents[i];
        hep_do(h, &rq, &r);
        Sleep(50);
        t_note("OBS inject agent [%s] -> %s reqs=%d raw=%s", hep_esc(agents[i], strlen(agents[i])), hep_sig(&r, 0), srv_req_count(h->s), srv_req_count(h->s) ? hep_raw(h->s, 0) : "-");
        /* Win10 VM: the agent is cut at the first CR or LF */
        CHECK(r.ok);
        if (srv_req_count(h->s)) { EXPECT_HDR(h->s, 0, "User-Agent", "ua"); EXPECT_NOHDR(h->s, 0, "X-Inj"); }
        EXPECT_EQ(srv_req_count(h->s) <= 1, 1);
        hep_stop(h);
    }
}
GTEST(hep_inject_referrer_crlf, 60000) {
    HEP_REQUIRE_HTTP();
    static const char *refs[] = { "http://r.example/\r\nX-Inj: 1", "http://r.example/a b", "http://r.example/\xe9" };
    for (int i = 0; i < 3; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/r", NULL, refs[i], NULL, HEP_F, 0);
        BOOL ok = hr && U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
        if (ok) srv_wait_requests(h->s, 1, 2000);
        t_note("OBS referrer [%s] -> open=%d ok=%d raw=%s", hep_esc(refs[i], strlen(refs[i])), hr != NULL, ok, ok ? hep_raw(h->s, 0) : "-");
        /* Win10 VM: cut at CR/LF, otherwise verbatim (no escaping of the space or the high byte) */
        static const char *want[] = { "http://r.example/", "http://r.example/a b", "http://r.example/\xe9" };
        CHECK(ok);
        if (ok) { EXPECT_HDR(h->s, 0, "Referer", want[i]); EXPECT_NOHDR(h->s, 0, "X-Inj"); }
        if (hr) U(InternetCloseHandle)(hr);
        U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
    }
}

/* ------------------------------------------------------------ A vs W non-ASCII headers */
GTEST(hep_nonascii_send_headers_a_verbatim, 60000) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    rq_out o; CHECK(one(h, "GET", "/a", NULL, "X-U: \xc3\xa9\xe9\x80\xff\r\n", (DWORD)-1, NULL, 0, &o));
    const char *v = srv_req_header(h->s, 0, "X-U");
    CHECK(v != NULL);
    if (v) EXPECT_STR(hep_esc(v, strlen(v)), "\\xc3\\xa9\\xe9\\x80\\xff");
    hep_stop(h);
}
static void w_send_case(const WCHAR *hdr, const char *tag, int via_add, const char *want) {
    hep_srv *h = hep_start_ok(); if (!h) return;
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestW)(hc, L"GET", L"/w", NULL, NULL, NULL, HEP_F, 0);
    BOOL ok;
    if (via_add) { BOOL a = U(HttpAddRequestHeadersW)(hr, hdr, (DWORD)-1, HTTP_ADDREQ_FLAG_ADD); CHECKF(a, "%s add err %lu", tag, GetLastError()); ok = U(HttpSendRequestW)(hr, NULL, 0, NULL, 0); }
    else ok = U(HttpSendRequestW)(hr, hdr, (DWORD)-1, NULL, 0);
    CHECKF(ok, "%s err %lu", tag, ok ? 0 : GetLastError());
    if (ok && srv_wait_requests(h->s, 1, 2000)) {
        const char *v = srv_req_header(h->s, 0, "X-U");
        t_note("OBS W %s %s -> %s", via_add ? "add" : "send", tag, v ? hep_esc(v, strlen(v)) : "(absent)");
        CHECK(v != NULL);
        if (v) t_check(!strcmp(hep_esc(v, strlen(v)), want), __FILE__, __LINE__, tag, "got %s want %s", hep_esc(v, strlen(v)), want);
    }
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_nonascii_w_send_headers, 60000) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpSendRequestW));
    w_send_case(L"X-U: \x00e9\r\n", "e_acute", 0, "\\xc3\\xa9");
    w_send_case(L"X-U: \x20ac\r\n", "euro", 0, "\\xe2\\x82\\xac");
    w_send_case(L"X-U: \x4e2d\x6587\r\n", "cjk", 0, "\\xe4\\xb8\\xad\\xe6\\x96\\x87");
    w_send_case(L"X-U: \x2603\r\n", "snowman", 0, "\\xe2\\x98\\x83");
    w_send_case(L"X-U: \xd83d\xde00\r\n", "emoji_pair", 0, "\\xf0\\x9f\\x98\\x80");
    w_send_case(L"X-U: \xd83d\r\n", "lone_surrogate", 0, "\\xef\\xbf\\xbd");
    w_send_case(L"X-U: \x0080\x00ff\r\n", "latin1_range", 0, "\\xc2\\x80\\xc3\\xbf");
}
GTEST(hep_nonascii_w_add_headers, 60000) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpSendRequestW)); REQUIRE(U(HttpAddRequestHeadersW));
    w_send_case(L"X-U: \x00e9", "e_acute", 1, "\\xc3\\xa9");
    w_send_case(L"X-U: \x20ac", "euro", 1, "\\xe2\\x82\\xac");
    w_send_case(L"X-U: \x4e2d\x6587", "cjk", 1, "\\xe4\\xb8\\xad\\xe6\\x96\\x87");
    w_send_case(L"X-U: \x2603", "snowman", 1, "\\xe2\\x98\\x83");
}
GTEST(hep_nonascii_w_add_headers_utf8, 60000) {
    /* decomp: HttpAddRequestHeadersW converts with CP_UTF8 */
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpSendRequestW)); REQUIRE(U(HttpAddRequestHeadersW));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestW)(hc, L"GET", L"/w", NULL, NULL, NULL, HEP_F, 0);
    CHECK(U(HttpAddRequestHeadersW)(hr, L"X-U: \x4e2d", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(U(HttpSendRequestW)(hr, NULL, 0, NULL, 0));
    CHECK(srv_wait_requests(h->s, 1, 2000));
    const char *v = srv_req_header(h->s, 0, "X-U");
    CHECK(v != NULL);
    if (v) EXPECT_STR(hep_esc(v, strlen(v)), "\\xe4\\xb8\\xad");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_nonascii_w_header_name, 60000) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpSendRequestW)); REQUIRE(U(HttpAddRequestHeadersW));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestW)(hc, L"GET", L"/w", NULL, NULL, NULL, HEP_F, 0);
    BOOL a = U(HttpAddRequestHeadersW)(hr, L"X-\x00e9: v", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD);
    DWORD ae = a ? 0 : GetLastError();
    BOOL ok = U(HttpSendRequestW)(hr, NULL, 0, NULL, 0);
    if (ok) srv_wait_requests(h->s, 1, 2000);
    t_note("OBS W non-ASCII header name: add=%d/%lu send=%d raw=%s", a, ae, ok, ok ? hep_raw(h->s, 0) : "-");
    CHECK(a); CHECK(ok);
    if (ok) EXPECT_STR(srv_req_header(h->s, 0, "X-\xc3\xa9"), "v");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_nonascii_w_query_request_header_back, 60000) {
    /* request header stored as UTF-8 bytes, HttpQueryInfoW converts back with ACP (decomp HttpQueryInfoW) */
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpAddRequestHeadersW)); REQUIRE(U(HttpQueryInfoW));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestW)(hc, L"GET", L"/w", NULL, NULL, NULL, HEP_F, 0);
    CHECK(U(HttpAddRequestHeadersW)(hr, L"X-U: \x00e9", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    WCHAR b[64]; DWORD l = sizeof b; wcscpy(b, L"X-U");
    BOOL q = U(HttpQueryInfoW)(hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_REQUEST_HEADERS, b, &l, NULL);
    CHECK(q);
    if (q) { t_note("OBS W query back: len=%lu chars=%04x %04x %04x", l, b[0], l > 2 ? b[1] : 0, l > 4 ? b[2] : 0);
             /* Win10 VM: the UTF-8 bytes come back through the ACP (1252 here): two characters, 4 bytes */
             EXPECT_EQ(l, 4); EXPECT_EQ(b[0], 0x00c3); EXPECT_EQ(b[1], 0x00a9); EXPECT_EQ(b[2], 0); }
    char a[64]; DWORD al = sizeof a; strcpy(a, "X-U");
    q = U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_REQUEST_HEADERS, a, &al, NULL);
    CHECK(q);
    if (q) EXPECT_STR(hep_esc(a, al), "\\xc3\\xa9");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_nonascii_w_verb_and_version, 60000) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpSendRequestW));
    static const WCHAR *verbs_w[] = { L"G\x00e9T", L"G\x4e2dT" };
    for (int i = 0; i < 2; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
        HINTERNET hr = U(HttpOpenRequestW)(hc, verbs_w[i], L"/w", NULL, NULL, NULL, HEP_F, 0);
        BOOL ok = hr && U(HttpSendRequestW)(hr, NULL, 0, NULL, 0);
        if (ok) srv_wait_requests(h->s, 1, 2000);
        const char *m = ok ? srv_req_method(h->s, 0) : NULL;
        t_note("OBS W verb %d -> open=%d ok=%d method=%s err=%lu", i, hr != NULL, ok, m ? hep_esc(m, strlen(m)) : "-", hr ? 0 : GetLastError());
        CHECK(hr == NULL);   /* Win10 VM: non-ASCII W verbs are refused by HttpOpenRequestW */
        if (hr) U(InternetCloseHandle)(hr);
        U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
    }
}

/* ------------------------------------------------------------ HttpAddRequestHeaders on a sent request */
GTEST(hep_add_after_send_succeeds_and_applies_to_resend, 60000) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpAddRequestHeadersA));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/as", NULL, NULL, NULL, HEP_F, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    char b[16]; t_inet_read_all(hr, b, sizeof b, NULL);
    SetLastError(0xdead);
    BOOL a = U(HttpAddRequestHeadersA)(hr, "X-Late: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD);
    t_note("OBS add after send: %d err %lu", a, a ? 0 : GetLastError());
    CHECK(a);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    t_inet_read_all(hr, b, sizeof b, NULL);
    CHECK(srv_wait_requests(h->s, 2, 2000));
    EXPECT_NOHDR(h->s, 0, "X-Late");
    EXPECT_HDR(h->s, 1, "X-Late", "1");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_add_after_send_replace_host, 60000) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpAddRequestHeadersA));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/as", NULL, NULL, NULL, HEP_F, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    char b[16]; t_inet_read_all(hr, b, sizeof b, NULL);
    BOOL a = U(HttpAddRequestHeadersA)(hr, "Host: other.example", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD);
    DWORD ae = a ? 0 : GetLastError();
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    if (ok) t_inet_read_all(hr, b, sizeof b, NULL);
    srv_wait_requests(h->s, 2, 2000);
    t_note("OBS replace Host after send: add=%d/%lu resend=%d host0=%s host1=%s", a, ae, ok, srv_req_header(h->s, 0, "Host"), srv_req_header(h->s, 1, "Host"));
    CHECK(a); CHECK(ok);
    EXPECT_HDR(h->s, 1, "Host", "other.example");
    EXPECT_HDR(h->s, 0, "Host", hep_hostport(h));
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_add_between_send_and_read, 60000) {
    /* adding while the response body is still unread does not disturb the read */
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpAddRequestHeadersA));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/as", NULL, NULL, NULL, HEP_F, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    CHECK(U(HttpAddRequestHeadersA)(hr, "X-Mid: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    char b[16]; int ok; size_t n = t_inet_read_all(hr, b, sizeof b, &ok);
    CHECK(ok); EXPECT_EQ(n, 2); EXPECT_STR(b, "ok");
    char q[64]; DWORD l = sizeof q; strcpy(q, "X-Mid");
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_REQUEST_HEADERS, q, &l, NULL));
    EXPECT_STR(q, "1");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_add_remove_after_send, 60000) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpAddRequestHeadersA));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/as", NULL, NULL, NULL, HEP_F, 0);
    CHECK(U(HttpAddRequestHeadersA)(hr, "X-Gone: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    char b[16]; t_inet_read_all(hr, b, sizeof b, NULL);
    CHECK(U(HttpAddRequestHeadersA)(hr, "X-Gone:", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE));
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    t_inet_read_all(hr, b, sizeof b, NULL);
    CHECK(srv_wait_requests(h->s, 2, 2000));
    EXPECT_HDR(h->s, 0, "X-Gone", "1");
    EXPECT_NOHDR(h->s, 1, "X-Gone");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_send_headers_not_sticky_across_resend, 60000) {
    /* headers passed to HttpSendRequest: are they kept for the next HttpSendRequest on the same handle? */
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/as", NULL, NULL, NULL, HEP_F, 0);
    CHECK(U(HttpSendRequestA)(hr, "X-Once: 1\r\n", (DWORD)-1, NULL, 0));
    char b[16]; t_inet_read_all(hr, b, sizeof b, NULL);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    t_inet_read_all(hr, b, sizeof b, NULL);
    CHECK(srv_wait_requests(h->s, 2, 2000));
    EXPECT_HDR(h->s, 0, "X-Once", "1");
    t_note("OBS send headers on resend: %s", srv_req_header(h->s, 1, "X-Once") ? "kept" : "dropped");
    EXPECT_HDR(h->s, 1, "X-Once", "1");   /* Win10 VM: HttpSendRequest headers stay on the handle */
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}

/* ------------------------------------------------------------ request header sizes and counts */
static void big_req_header(size_t vlen) {
    hep_srv *h = hep_start_ok(); if (!h) return;
    char *hdr = (char *)malloc(vlen + 32);
    size_t n = (size_t)sprintf(hdr, "X-Big: ");
    for (size_t i = 0; i < vlen; i++) hdr[n++] = (char)('a' + i % 26);
    strcpy(hdr + n, "\r\n");
    rq_out o; one(h, "GET", "/big", NULL, hdr, (DWORD)-1, NULL, 0, &o);
    const char *v = o.ok ? srv_req_header(h->s, 0, "X-Big") : NULL;
    t_note("OBS request header %zu bytes -> ok=%d err=%lu seen=%zu", vlen, o.ok, o.err, v ? strlen(v) : 0);
    CHECK(o.ok);
    if (v) EXPECT_EQ(strlen(v), vlen);
    free(hdr); hep_stop(h);
}
GTEST(hep_req_header_value_8k, 60000)   { HEP_REQUIRE_HTTP(); big_req_header(8192); }
GTEST(hep_req_header_value_64k, 60000)  { HEP_REQUIRE_HTTP(); big_req_header(65536); }
GTEST(hep_req_header_value_200k, 60000) { HEP_REQUIRE_HTTP(); big_req_header(200000); }
GTEST(hep_req_header_count_500, 60000) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpAddRequestHeadersA));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/many", NULL, NULL, NULL, HEP_F, 0);
    int added = 0;
    for (int i = 0; i < 500; i++) { char l[64]; snprintf(l, sizeof l, "X-N%d: %d", i, i); added += !!U(HttpAddRequestHeadersA)(hr, l, (DWORD)-1, HTTP_ADDREQ_FLAG_ADD); }
    EXPECT_EQ(added, 500);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    CHECK(srv_wait_requests(h->s, 1, 2000));
    EXPECT_HDR(h->s, 0, "X-N0", "0"); EXPECT_HDR(h->s, 0, "X-N499", "499");
    EXPECT_EQ(srv_req_header_index(h->s, 0, "X-N499") - srv_req_header_index(h->s, 0, "X-N0"), 499);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
