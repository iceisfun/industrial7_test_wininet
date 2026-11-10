/* wire_addhdr.c - HttpAddRequestHeaders and HttpSendRequest header strings, asserted on the wire.
 * Evidence: HttpAddRequestHeadersA@0x88990 (NULL/""/len 0/flags & 0x08ff0000 rejected), wHttpAddRequestHeaders@0x898d0
 * (line split on CR/LF, name to first ':', empty value -> 87 unless REPLACE/ADD_IF_NEW or ALLOW_EMPTY_VALUES,
 * REPLACE path), CHttpHeaders::AddHeaderByName@0x8ab70 (name/value SP/TAB trimmed, trailing ':' stripped,
 * COALESCE 0x41000000), and the Win10 VM. See EVIDENCE.md. */
#include "hrw.h"

static BOOL add(HINTERNET hr, const char *h, DWORD len, DWORD flags) {
    SetLastError(0xdeadbeef);
    return U(HttpAddRequestHeadersA)(hr, h, len, flags);
}

/* Open a request on a fresh default server; NULL server -> skip */
#define OPEN_OR_SKIP(w, verb, path) \
    REQUIRE(U(HttpAddRequestHeadersA)); HRW_REQUIRE_HTTP(); \
    srv *s_ = hrw_srv(); if (!s_) { t_skip("server unavailable"); return; } \
    hrw w; CHECK(hrw_open(&w, s_, "ah/1", verb, path, NULL, NULL, NULL, HRW_F))
#define SEND_AND_WAIT(w) do { hrw_send(&(w), NULL, 0, NULL, 0); CHECKF((w).ok, "send err %lu %s", (w).err, t_inet_errname((w).err)); \
    if ((w).ok) hrw_read(&(w)); CHECK(srv_wait_requests((w).s, 1, 3000)); } while (0)

/* ------------------------------------------------------------------ basic add, position, casing */
TEST(hrw_add_simple) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Test: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Test", "1");
    EXPECT_NAMES(w.s, 0, "X-Test|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add_flags_zero) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Zero: z", (DWORD)-1, 0));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Zero", "z");
    hrw_done(&w);
}
TEST(hrw_add_name_casing_preserved) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "x-LoWeR-cAsE: MiXeD Value", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_STR(srv_req_header_name(w.s, 0, 0), "x-LoWeR-cAsE");
    EXPECT_STR(srv_req_header_value(w.s, 0, 0), "MiXeD Value");
    hrw_done(&w);
}
TEST(hrw_add_value_whitespace_trimmed) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Ws:  \t  padded value \t ", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    const char *raw = hrw_raw(w.s, 0);
    CHECKF(strstr(raw, "\r\nX-Ws: padded value\r\n") != NULL, "raw: %s", raw);
    hrw_done(&w);
}
TEST(hrw_add_name_whitespace_trimmed) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "  X-Nm  : v", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    const char *raw = hrw_raw(w.s, 0);
    CHECKF(strstr(raw, "\r\nX-Nm: v\r\n") != NULL, "raw: %s", raw);
    hrw_done(&w);
}
TEST(hrw_add_no_space_after_colon) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Tight:tight", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    const char *raw = hrw_raw(w.s, 0);
    CHECKF(strstr(raw, "\r\nX-Tight: tight\r\n") != NULL, "raw: %s", raw);
    hrw_done(&w);
}
TEST(hrw_add_value_with_colons) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Url: http://a.example:81/p?x=1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Url", "http://a.example:81/p?x=1");
    hrw_done(&w);
}
TEST(hrw_add_double_colon) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Dc:: v", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    const char *raw = hrw_raw(w.s, 0);
    CHECKF(strstr(raw, "\r\nX-Dc: v\r\n") != NULL, "raw: %s", raw);
    hrw_done(&w);
}
TEST(hrw_add_multi_lines_crlf) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-1: a\r\nX-2: b\r\nX-3: c\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_NAMES(w.s, 0, "X-1|X-2|X-3|User-Agent|Host|Cache-Control");
    EXPECT_HDR(w.s, 0, "X-2", "b");
    hrw_done(&w);
}
TEST(hrw_add_multi_lines_lf_only) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-1: a\nX-2: b\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_NAMES(w.s, 0, "X-1|X-2|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add_multi_lines_blank_lines_skipped) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "\r\n\r\nX-1: a\r\n\r\n\r\nX-2: b\r\n\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_NAMES(w.s, 0, "X-1|X-2|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add_only_crlf_is_ok_noop) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_NAMES(w.s, 0, "User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add_separate_calls_keep_order) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-B: 2", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "X-A: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "X-C: 3", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_NAMES(w.s, 0, "X-B|X-A|X-C|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add_many_headers) {
    OPEN_OR_SKIP(w, "GET", "/a");
    char h[64];
    for (int i = 0; i < 60; i++) { snprintf(h, sizeof h, "X-H%02d: v%d", i, i); CHECK(add(w.hr, h, (DWORD)-1, HTTP_ADDREQ_FLAG_ADD)); }
    SEND_AND_WAIT(w);
    EXPECT_EQ(srv_req_header_count(w.s, 0), 63);
    for (int i = 0; i < 60; i++) {
        snprintf(h, sizeof h, "X-H%02d", i);
        CHECKF(srv_req_header_index(w.s, 0, h) == i, "%s at %d", h, srv_req_header_index(w.s, 0, h));
    }
    hrw_done(&w);
}
TEST(hrw_add_big_value) {
    OPEN_OR_SKIP(w, "GET", "/a");
    static char h[9000]; memcpy(h, "X-Big: ", 7);
    for (int i = 0; i < 8000; i++) h[7 + i] = (char)('a' + i % 26);
    h[8007] = 0;
    CHECK(add(w.hr, h, (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    const char *v = srv_req_header(w.s, 0, "X-Big");
    CHECK(v && strlen(v) == 8000 && !memcmp(v, h + 7, 8000));
    hrw_done(&w);
}
TEST(hrw_add_high_bytes_raw) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Hi: caf\xc3\xa9 \xe9", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Hi", "caf\xc3\xa9 \xe9");
    hrw_done(&w);
}
TEST(hrw_add_w_nonascii_value) {
    OPEN_OR_SKIP(w, "GET", "/a");
    REQUIRE(U(HttpAddRequestHeadersW));
    CHECK(U(HttpAddRequestHeadersW)(w.hr, L"X-Wide: \u00e9\u4e2d", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    const char *v = srv_req_header(w.s, 0, "X-Wide");
    t_note("W header value bytes: %s", v ? v : "(none)");
    EXPECT_STR(v, "\xc3\xa9\xe4\xb8\xad");
    hrw_done(&w);
}
TEST(hrw_add_w_ascii) {
    OPEN_OR_SKIP(w, "GET", "/a");
    REQUIRE(U(HttpAddRequestHeadersW));
    CHECK(U(HttpAddRequestHeadersW)(w.hr, L"X-W1: one\r\nX-W2: two", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_NAMES(w.s, 0, "X-W1|X-W2|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add_w_length_chars) {
    OPEN_OR_SKIP(w, "GET", "/a");
    REQUIRE(U(HttpAddRequestHeadersW));
    CHECK(U(HttpAddRequestHeadersW)(w.hr, L"X-Len: abcdef", 10, HTTP_ADDREQ_FLAG_ADD));   /* "X-Len: abc" */
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Len", "abc");
    hrw_done(&w);
}

/* ------------------------------------------------------------------ length parameter (A) */
TEST(hrw_add_len_exact) {
    OPEN_OR_SKIP(w, "GET", "/a");
    static const char h[] = "X-Ex: exact";
    CHECK(add(w.hr, h, sizeof h - 1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Ex", "exact");
    hrw_done(&w);
}
TEST(hrw_add_len_prefix_truncates_value) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Pre: abcdef", 9, HTTP_ADDREQ_FLAG_ADD));   /* "X-Pre: ab" */
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Pre", "ab");
    hrw_done(&w);
}
TEST(hrw_add_len_prefix_drops_second_line) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-1: a\r\nX-2: b", 8, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_NAMES(w.s, 0, "X-1|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add_len_cuts_name_rejected) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(!add(w.hr, "X-Cut: v", 4, HTTP_ADDREQ_FLAG_ADD));  /* "X-Cu": no colon */
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SEND_AND_WAIT(w);
    EXPECT_NAMES(w.s, 0, "User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add_len_zero_rejected) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(!add(w.hr, "X-Z: v", 0, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    hrw_done(&w);
}
TEST(hrw_add_null_rejected) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(!add(w.hr, NULL, (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    hrw_done(&w);
}
TEST(hrw_add_empty_string_rejected) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(!add(w.hr, "", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    hrw_done(&w);
}

/* ------------------------------------------------------------------ malformed lines */
TEST(hrw_add_no_colon_rejected) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(!add(w.hr, "NoColonHere", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SEND_AND_WAIT(w);
    EXPECT_NAMES(w.s, 0, "User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add_empty_value_rejected) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(!add(w.hr, "X-Empty:", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(!add(w.hr, "X-Empty:   \t", (DWORD)-1, 0));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SEND_AND_WAIT(w);
    EXPECT_NOHDR(w.s, 0, "X-Empty");
    hrw_done(&w);
}
TEST(hrw_add_empty_name_rejected) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(!add(w.hr, ": value", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    hrw_done(&w);
}
TEST(hrw_add_allow_empty_values) {
    OPEN_OR_SKIP(w, "GET", "/a");
    BOOL ok = add(w.hr, "X-Empty:", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_ALLOW_EMPTY_VALUES);
    CHECKF(ok, "err %lu", GetLastError());
    SEND_AND_WAIT(w);
    CHECK(srv_req_header_index(w.s, 0, "X-Empty") >= 0);
    EXPECT_HDR(w.s, 0, "X-Empty", "");
    hrw_dump(w.s, 0);
    hrw_done(&w);
}
TEST(hrw_add_first_line_bad_second_good) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(!add(w.hr, "Bad\r\nX-Good: g", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SEND_AND_WAIT(w);
    EXPECT_NOHDR(w.s, 0, "X-Good");
    hrw_done(&w);
}
TEST(hrw_add_first_line_good_second_bad) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(!add(w.hr, "X-Good: g\r\nBad", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Good", "g");   /* lines are applied one at a time */
    hrw_done(&w);
}

/* ------------------------------------------------------------------ flag validation and handle checks */
static void bad_flags(DWORD f) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECKF(!add(w.hr, "X-F: 1", (DWORD)-1, f), "flags 0x%lx accepted", f);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    hrw_done(&w);
}
TEST(hrw_add_flag_0x00010000_rejected) { bad_flags(0x00010000); }
TEST(hrw_add_flag_0x00800000_rejected) { bad_flags(0x00800000); }
TEST(hrw_add_flag_0x08000000_rejected) { bad_flags(0x08000000); }
TEST(hrw_add_flag_add_plus_reserved_rejected) { bad_flags(HTTP_ADDREQ_FLAG_ADD | 0x00100000); }
TEST(hrw_add_low_word_flags_ok) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Lo: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD | 0x0000ffff));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Lo", "1");
    hrw_done(&w);
}
TEST(hrw_add_null_handle) {
    REQUIRE(U(HttpAddRequestHeadersA));
    CHECK(!add(NULL, "X: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(hrw_add_session_handle) {
    REQUIRE(U(HttpAddRequestHeadersA));
    HINTERNET hi = t_inet_open("x"); CHECK(hi != NULL);
    CHECK(!add(hi, "X: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    t_inet_close(hi);
}
TEST(hrw_add_connect_handle) {
    REQUIRE(U(HttpAddRequestHeadersA));
    HINTERNET hi = t_inet_open("x");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 1, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(hc != NULL);
    CHECK(!add(hc, "X: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    U(InternetCloseHandle)(hc); t_inet_close(hi);
}
TEST(hrw_add_success_lasterror) {
    OPEN_OR_SKIP(w, "GET", "/a");
    SetLastError(0xdeadbeef);
    CHECK(U(HttpAddRequestHeadersA)(w.hr, "X-Le: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_EQ(GetLastError(), 0);   /* Win10 VM: success clears the last error */
    hrw_done(&w);
}

/* ------------------------------------------------------------------ ADD / ADD_IF_NEW / REPLACE / COALESCE */
TEST(hrw_add_twice_duplicates) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Dup: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "X-Dup: 2", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "X-Dup"), 2);
    EXPECT_NAMES(w.s, 0, "X-Dup|X-Dup|User-Agent|Host|Cache-Control");
    EXPECT_STR(srv_req_header_value(w.s, 0, 0), "1");
    EXPECT_STR(srv_req_header_value(w.s, 0, 1), "2");
    hrw_done(&w);
}
TEST(hrw_add_flags0_twice_duplicates) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Dup: 1", (DWORD)-1, 0));
    CHECK(add(w.hr, "x-dup: 2", (DWORD)-1, 0));
    SEND_AND_WAIT(w);
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "X-Dup"), 2);
    EXPECT_STR(srv_req_header_name(w.s, 0, 1), "x-dup");
    hrw_done(&w);
}
TEST(hrw_add_if_new_absent_ok) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-New: n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD_IF_NEW));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-New", "n");
    hrw_done(&w);
}
TEST(hrw_add_if_new_present_fails) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-New: first", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(!add(w.hr, "X-New: second", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD_IF_NEW));
    EXPECT_ERR(ERROR_HTTP_HEADER_ALREADY_EXISTS);
    CHECK(!add(w.hr, "x-new: third", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD_IF_NEW));
    EXPECT_ERR(ERROR_HTTP_HEADER_ALREADY_EXISTS);
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-New", "first");
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "X-New"), 1);
    hrw_done(&w);
}
TEST(hrw_add_if_new_user_agent_before_send) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "User-Agent: mine", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD_IF_NEW));   /* UA is only added at send */
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "User-Agent", "mine");
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "User-Agent"), 1);
    hrw_done(&w);
}
TEST(hrw_add_user_agent_overrides_session) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "User-Agent: custom/9", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "User-Agent", "custom/9");
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "User-Agent"), 1);
    EXPECT_NAMES(w.s, 0, "User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add_user_agent_lowercase_name) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "user-agent: lc", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "User-Agent"), 1);
    EXPECT_HDR(w.s, 0, "User-Agent", "lc");
    EXPECT_STR(srv_req_header_name(w.s, 0, srv_req_header_index(w.s, 0, "User-Agent")), "user-agent");   /* VM */
    hrw_done(&w);
}
TEST(hrw_replace_existing) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-R: old\r\nX-Other: o", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "X-R: new", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-R", "new");
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "X-R"), 1);
    /* Win10 VM: REPLACE removes the old line and appends the new one at the end of the caller headers */
    EXPECT_NAMES(w.s, 0, "X-Other|X-R|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
/* Win10 VM: REPLACE without ADD on an absent header still adds it (no 12150). */
TEST(hrw_replace_absent_adds) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Missing: v", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Missing", "v");
    EXPECT_NAMES(w.s, 0, "X-Missing|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_replace_or_add_absent_adds) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Ra: v", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Ra", "v");
    hrw_done(&w);
}
TEST(hrw_replace_or_add_present_replaces) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Ra: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "X-Ra: 2", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Ra", "2");
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "X-Ra"), 1);
    hrw_done(&w);
}
TEST(hrw_replace_empty_value_removes) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Gone: v\r\nX-Stay: s", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "X-Gone:", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE));
    SEND_AND_WAIT(w);
    EXPECT_NOHDR(w.s, 0, "X-Gone");
    EXPECT_HDR(w.s, 0, "X-Stay", "s");
    hrw_done(&w);
}
TEST(hrw_replace_case_insensitive_keeps_new_name) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Case: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "x-CASE: 2", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE));
    SEND_AND_WAIT(w);
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "X-Case"), 1);
    EXPECT_HDR(w.s, 0, "X-Case", "2");
    EXPECT_STR(srv_req_header_name(w.s, 0, srv_req_header_index(w.s, 0, "x-case")), "x-CASE");   /* VM: new spelling */
    hrw_done(&w);
}
TEST(hrw_replace_duplicate_replaces_first) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-D: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "X-D: 2", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "X-D: 3", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE));
    SEND_AND_WAIT(w);
    /* Win10 VM: the first occurrence is removed and the new value appended: X-D: 2, X-D: 3 */
    EXPECT_NAMES(w.s, 0, "X-D|X-D|User-Agent|Host|Cache-Control");
    EXPECT_STR(srv_req_header_value(w.s, 0, 0), "2");
    EXPECT_STR(srv_req_header_value(w.s, 0, 1), "3");
    hrw_done(&w);
}
TEST(hrw_coalesce_comma) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Co: a", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "X-Co: b", (DWORD)-1, HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA));
    CHECK(add(w.hr, "X-Co: c", (DWORD)-1, HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Co", "a, b, c");
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "X-Co"), 1);
    hrw_done(&w);
}
TEST(hrw_coalesce_plain_flag_is_comma) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Co: a", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "X-Co: b", (DWORD)-1, HTTP_ADDREQ_FLAG_COALESCE));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Co", "a, b");
    hrw_done(&w);
}
TEST(hrw_coalesce_semicolon) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Sc: a=1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "X-Sc: b=2", (DWORD)-1, HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Sc", "a=1; b=2");
    hrw_done(&w);
}
TEST(hrw_coalesce_absent_adds) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Ca: only", (DWORD)-1, HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA));
    SEND_AND_WAIT(w);
    EXPECT_HDR(w.s, 0, "X-Ca", "only");
    hrw_done(&w);
}
TEST(hrw_coalesce_case_insensitive_name) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Ci: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(add(w.hr, "x-ci: 2", (DWORD)-1, HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA));
    SEND_AND_WAIT(w);
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "X-Ci"), 1);
    EXPECT_HDR(w.s, 0, "X-Ci", "1, 2");
    EXPECT_STR(srv_req_header_name(w.s, 0, 0), "X-Ci");
    hrw_done(&w);
}
TEST(hrw_coalesce_with_accept_types) {
    REQUIRE(U(HttpAddRequestHeadersA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    static const char *t[] = { "text/html", NULL };
    hrw w; CHECK(hrw_open(&w, s, "ca/1", "GET", "/a", NULL, NULL, t, HRW_F));
    CHECK(add(w.hr, "Accept: image/png", (DWORD)-1, HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA));
    SEND_AND_WAIT(w);
    EXPECT_HDR(s, 0, "Accept", "text/html, image/png");
    hrw_done(&w);
}
TEST(hrw_replace_accept_types) {
    REQUIRE(U(HttpAddRequestHeadersA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    static const char *t[] = { "text/html", NULL };
    hrw w; CHECK(hrw_open(&w, s, "ca/1", "GET", "/a", NULL, NULL, t, HRW_F));
    CHECK(add(w.hr, "Accept: */*", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE));
    SEND_AND_WAIT(w);
    EXPECT_HDR(s, 0, "Accept", "*/*");
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Accept"), 1);
    hrw_done(&w);
}
TEST(hrw_remove_referer_with_replace) {
    REQUIRE(U(HttpAddRequestHeadersA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rr/1", "GET", "/a", NULL, "http://ref.example/", NULL, HRW_F));
    CHECK(add(w.hr, "Referer:", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE));
    SEND_AND_WAIT(w);
    EXPECT_NOHDR(s, 0, "Referer");
    hrw_done(&w);
}

/* ------------------------------------------------------------------ headers passed to HttpSendRequest */
static void send_hdrs(const char *hdrs, DWORD len, BOOL want_ok, DWORD want_err, const char *names) {
    REQUIRE(U(HttpSendRequestA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "sh/1", "GET", "/s", NULL, NULL, NULL, HRW_F));
    hrw_send(&w, hdrs, len, NULL, 0);
    CHECKF(w.ok == want_ok, "send ok=%d err=%lu want ok=%d", w.ok, w.err, want_ok);
    if (!want_ok) CHECKF(w.err == want_err, "err %lu want %lu", w.err, want_err);
    if (w.ok) { hrw_read(&w); CHECK(srv_wait_requests(s, 1, 3000)); }
    if (names) EXPECT_NAMES(s, 0, names);
    if (!want_ok) { Sleep(50); EXPECT_EQ(srv_req_count(s), 0); }
    hrw_done(&w);
}
TEST(hrw_send_hdrs_minus1) { send_hdrs("X-S1: a\r\nX-S2: b\r\n", (DWORD)-1, TRUE, 0, "X-S1|X-S2|User-Agent|Host|Cache-Control"); }
TEST(hrw_send_hdrs_exact_len) { static const char h[] = "X-S1: a\r\n"; send_hdrs(h, sizeof h - 1, TRUE, 0, "X-S1|User-Agent|Host|Cache-Control"); }
TEST(hrw_send_hdrs_no_trailing_crlf) { send_hdrs("X-S1: a", (DWORD)-1, TRUE, 0, "X-S1|User-Agent|Host|Cache-Control"); }
TEST(hrw_send_hdrs_prefix_len) { send_hdrs("X-S1: a\r\nX-S2: b\r\n", 9, TRUE, 0, "X-S1|User-Agent|Host|Cache-Control"); }
TEST(hrw_send_hdrs_len0_nonnull_a) { send_hdrs("X-S1: a\r\n", 0, FALSE, ERROR_INVALID_PARAMETER, NULL); }
TEST(hrw_send_hdrs_null_len_minus1) { send_hdrs(NULL, (DWORD)-1, TRUE, 0, "User-Agent|Host|Cache-Control"); }
TEST(hrw_send_hdrs_empty_string) { send_hdrs("", (DWORD)-1, TRUE, 0, "User-Agent|Host|Cache-Control"); }
TEST(hrw_send_hdrs_only_crlf) { send_hdrs("\r\n", (DWORD)-1, TRUE, 0, "User-Agent|Host|Cache-Control"); }
TEST(hrw_send_hdrs_double_crlf_terminated) { send_hdrs("X-S1: a\r\n\r\n", (DWORD)-1, TRUE, 0, "X-S1|User-Agent|Host|Cache-Control"); }
/* Win10 VM: a malformed line in the HttpSendRequest headers fails the send with 12150 (HttpAddRequestHeaders itself says 87) */
TEST(hrw_send_hdrs_no_colon) { send_hdrs("Garbage\r\n", (DWORD)-1, FALSE, ERROR_HTTP_HEADER_NOT_FOUND, NULL); }
TEST(hrw_send_hdrs_empty_value) { send_hdrs("X-E:\r\n", (DWORD)-1, FALSE, ERROR_HTTP_HEADER_NOT_FOUND, NULL); }

TEST(hrw_send_hdrs_replace_added_header) {
    REQUIRE(U(HttpAddRequestHeadersA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "sr/1", "GET", "/s", NULL, NULL, NULL, HRW_F));
    CHECK(add(w.hr, "X-Both: from-add", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    hrw_send(&w, "X-Both: from-send\r\n", (DWORD)-1, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "X-Both"), 1);
    EXPECT_HDR(s, 0, "X-Both", "from-send");
    hrw_done(&w);
}
TEST(hrw_send_hdrs_user_agent_overrides) {
    hrw w; int r = hrw_simple(&w, "session/1", "GET", "/s", NULL, NULL, NULL, HRW_F, "User-Agent: per-request/2\r\n", NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_HDR(w.s, 0, "User-Agent", "per-request/2");
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "User-Agent"), 1);
    hrw_done(&w);
}
TEST(hrw_send_hdrs_cache_control_override) {
    hrw w; int r = hrw_simple(&w, "cc/1", "GET", "/s", NULL, NULL, NULL, HRW_F, "Cache-Control: max-age=0\r\n", NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    /* Win10 VM: the caller's Cache-Control replaces the RELOAD default and keeps its (first) position */
    EXPECT_HDR(w.s, 0, "Cache-Control", "max-age=0");
    EXPECT_NAMES(w.s, 0, "Cache-Control|User-Agent|Host");
    hrw_done(&w);
}
TEST(hrw_send_hdrs_connection_close_sent) {
    hrw w; int r = hrw_simple(&w, "cl/1", "GET", "/s", NULL, NULL, NULL, HRW_F, "Connection: close\r\n", NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_HDR(w.s, 0, "Connection", "Close");   /* Win10 VM: WinINet re-spells the token */
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "Connection"), 1);
    hrw_done(&w);
}
TEST(hrw_send_hdrs_w_len0_is_nul_terminated) {
    REQUIRE(U(HttpSendRequestW)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "sw/1", "GET", "/s", NULL, NULL, NULL, HRW_F));
    BOOL ok = U(HttpSendRequestW)(w.hr, L"X-W: wide\r\n", 0, NULL, 0);
    CHECKF(ok, "err %lu", GetLastError());
    if (ok) { hrw_read(&w); CHECK(srv_wait_requests(s, 1, 3000)); EXPECT_HDR(s, 0, "X-W", "wide"); }
    hrw_done(&w);
}
TEST(hrw_send_hdrs_w_minus1) {
    REQUIRE(U(HttpSendRequestW)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "sw/1", "GET", "/s", NULL, NULL, NULL, HRW_F));
    BOOL ok = U(HttpSendRequestW)(w.hr, L"X-W1: 1\r\nX-W2: \u00e9\r\n", (DWORD)-1, NULL, 0);
    CHECKF(ok, "err %lu", GetLastError());
    if (ok) {
        hrw_read(&w); CHECK(srv_wait_requests(s, 1, 3000));
        EXPECT_NAMES(s, 0, "X-W1|X-W2|User-Agent|Host|Cache-Control");
        EXPECT_HDR(s, 0, "X-W2", "\xc3\xa9");
    }
    hrw_done(&w);
}

/* ------------------------------------------------------------------ after a send: headers persist for a re-send */
TEST(hrw_add_after_send_applies_to_resend) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-First: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    hrw_send(&w, "X-SendOnly: s\r\n", (DWORD)-1, NULL, 0); CHECK(w.ok); hrw_read(&w);
    SetLastError(0);
    BOOL ok = add(w.hr, "X-Second: 2", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD);
    DWORD e = GetLastError();
    CHECK(ok); EXPECT_EQ(e, 0);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    /* Win10 VM: after the first send the defaults are part of the block, so a later add lands after them */
    EXPECT_NAMES(w.s, 1, "X-First|X-SendOnly|User-Agent|Host|Cache-Control|X-Second|Connection");
    EXPECT_HDR(w.s, 1, "X-First", "1");
    EXPECT_HDR(w.s, 1, "X-Second", "2");
    EXPECT_EQ(srv_req_header_occurrences(w.s, 1, "X-First"), 1);
    hrw_done(&w);
}

/* request headers are queryable before the send, exactly as added */
TEST(hrw_query_request_header_before_send) {
    OPEN_OR_SKIP(w, "GET", "/a");
    CHECK(add(w.hr, "X-Q: query-me", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    char buf[64] = "X-Q"; DWORD l = sizeof buf;
    CHECK(U(HttpQueryInfoA)(w.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_REQUEST_HEADERS, buf, &l, NULL));
    EXPECT_STR(buf, "query-me"); EXPECT_EQ(l, 8);
    hrw_done(&w);
}
