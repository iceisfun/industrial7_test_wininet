/* http_auth: InternetErrorDlg on authentication results, never displaying UI.
 * Only paths that return before any window is created are exercised (decomp InternetErrorDlg@0x185430,
 * LaunchCredUI@0x184da8):
 *  - hRequest == NULL and dwError in {12014, 12034, 12044}  -> ERROR_INVALID_PARAMETER (87)
 *  - dwError 12053 (INSERT_CDROM)                            -> 120
 *  - 12014 path with neither FLAGS_ERROR_UI_FLAGS_NO_UI nor an hWnd -> 87 before any dialog
 *  - 12014 path with NO_UI: InetGetCachedCredentialsW instead of a dialog; FORCE_RETRY (12032) when cached
 *    credentials were applied, else ERROR_CANCELLED folded by LaunchCredUI.
 * FLAGS_ERROR_UI_FILTER_FOR_ERRORS maps a 401/407 request to 12014. */
#include "auth.h"

#define CH_BASIC "WWW-Authenticate: Basic realm=\"i7dlg\"\r\n"

static DWORD dlg(HWND w, HINTERNET h, DWORD err, DWORD flags) {
    LPVOID data = NULL;
    return U(InternetErrorDlg)(w, h, err, flags, &data);
}

TEST(auth_dlg_null_request_incorrect_password) {
    REQUIRE(U(InternetErrorDlg));
    EXPECT_EQ(dlg(NULL, NULL, ERROR_INTERNET_INCORRECT_PASSWORD, FLAGS_ERROR_UI_FLAGS_NO_UI), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(dlg(NULL, NULL, ERROR_INTERNET_INCORRECT_PASSWORD, FLAGS_ERROR_UI_FLAGS_NO_UI | FLAGS_ERROR_UI_FILTER_FOR_ERRORS), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(dlg(NULL, NULL, ERROR_INTERNET_INCORRECT_PASSWORD, FLAGS_ERROR_UI_FLAGS_NO_UI | FLAGS_ERROR_UI_FLAGS_GENERATE_DATA | FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS), ERROR_INVALID_PARAMETER);
}

TEST(auth_dlg_null_request_other_handle_errors) {
    REQUIRE(U(InternetErrorDlg));
    EXPECT_EQ(dlg(NULL, NULL, ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED, FLAGS_ERROR_UI_FLAGS_NO_UI), ERROR_INVALID_PARAMETER);   /* 12044 */
    EXPECT_EQ(dlg(NULL, NULL, 12034 /* ERROR_INTERNET_NEED_UI */, FLAGS_ERROR_UI_FLAGS_NO_UI), ERROR_INVALID_PARAMETER);
}

TEST(auth_dlg_insert_cdrom_not_supported) {
    REQUIRE(U(InternetErrorDlg));
    EXPECT_EQ(dlg(NULL, NULL, ERROR_INTERNET_INSERT_CDROM, FLAGS_ERROR_UI_FLAGS_NO_UI), ERROR_CALL_NOT_IMPLEMENTED);
}

TEST(auth_dlg_no_hwnd_no_noui_flag_rejected) {
    REQUIRE(U(InternetErrorDlg));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    EXPECT_EQ(r.status, 401);
    /* no NO_UI, no window: LaunchCredUI returns 87 before creating anything */
    EXPECT_EQ(dlg(NULL, r.hr, ERROR_INTERNET_INCORRECT_PASSWORD, 0), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(dlg(NULL, r.hr, ERROR_INTERNET_INCORRECT_PASSWORD, FLAGS_ERROR_UI_FLAGS_GENERATE_DATA | FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(dlg(NULL, r.hr, 0, FLAGS_ERROR_UI_FILTER_FOR_ERRORS), ERROR_INVALID_PARAMETER);   /* filter maps 401 -> 12014 */
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_dlg_no_ui_after_401_without_cached_creds) {
    REQUIRE(U(InternetErrorDlg));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    EXPECT_EQ(r.status, 401);
    DWORD d1 = dlg(NULL, r.hr, ERROR_INTERNET_INCORRECT_PASSWORD, FLAGS_ERROR_UI_FLAGS_NO_UI);
    DWORD d2 = dlg(NULL, r.hr, 0, FLAGS_ERROR_UI_FILTER_FOR_ERRORS | FLAGS_ERROR_UI_FLAGS_NO_UI);
    DWORD d3 = dlg(NULL, r.hr, ERROR_SUCCESS, FLAGS_ERROR_UI_FILTER_FOR_ERRORS | FLAGS_ERROR_UI_FLAGS_NO_UI | FLAGS_ERROR_UI_FLAGS_GENERATE_DATA | FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS);
    t_note("NO_UI on 401 without cached creds: 12014 -> %lu, filter -> %lu, filter+gen+chg -> %lu", d1, d2, d3);
    EXPECT_EQ(d1, d2);
    CHECK(d1 != ERROR_INTERNET_FORCE_RETRY);
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_dlg_no_ui_on_200_request) {
    REQUIRE(U(InternetErrorDlg));
    srv *s = srv_http(NULL, 0); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    EXPECT_EQ(r.status, 200);
    DWORD d1 = dlg(NULL, r.hr, ERROR_INTERNET_INCORRECT_PASSWORD, FLAGS_ERROR_UI_FLAGS_NO_UI);
    DWORD d2 = dlg(NULL, r.hr, ERROR_SUCCESS, FLAGS_ERROR_UI_FILTER_FOR_ERRORS | FLAGS_ERROR_UI_FLAGS_NO_UI);
    t_note("NO_UI on a 200 request: 12014 -> %lu; filter with err 0 -> %lu", d1, d2);
    CHECK(d1 != ERROR_INTERNET_FORCE_RETRY);
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_dlg_session_handle) {
    REQUIRE(U(InternetErrorDlg));
    HINTERNET hi = t_inet_open(NULL);
    DWORD d = dlg(NULL, hi, ERROR_INTERNET_INCORRECT_PASSWORD, FLAGS_ERROR_UI_FLAGS_NO_UI);
    t_note("InternetErrorDlg on a session handle: %lu", d);
    CHECK(d != ERROR_INTERNET_FORCE_RETRY);
    t_inet_close(hi);
}

TEST(auth_dlg_connect_handle) {
    REQUIRE(U(InternetErrorDlg));
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 9, "u", "p", INTERNET_SERVICE_HTTP, 0, 0);
    DWORD d = dlg(NULL, hc, ERROR_INTERNET_INCORRECT_PASSWORD, FLAGS_ERROR_UI_FLAGS_NO_UI);
    t_note("InternetErrorDlg on a connect handle: %lu", d);
    CHECK(d != ERROR_INTERNET_FORCE_RETRY);
    a_close(hc); t_inet_close(hi);
}

TEST(auth_dlg_no_ui_after_407) {
    REQUIRE(U(InternetErrorDlg));
    gate g = {0}; g.code = 407; g.challenge = "Proxy-Authenticate: Basic realm=\"i7dlgp\"\r\n"; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    char px[64]; snprintf(px, sizeof px, "127.0.0.1:%u", srv_port(s));
    HINTERNET hi = U(InternetOpenA)("i7dlg", INTERNET_OPEN_TYPE_PROXY, px, NULL, 0);
    HINTERNET hc = U(InternetConnectA)(hi, "i7origin.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    EXPECT_EQ(r.status, 407);
    DWORD d1 = dlg(NULL, r.hr, 0, FLAGS_ERROR_UI_FILTER_FOR_ERRORS | FLAGS_ERROR_UI_FLAGS_NO_UI);
    DWORD d2 = dlg(NULL, r.hr, 0, FLAGS_ERROR_UI_FILTER_FOR_ERRORS);
    t_note("407 + filter + NO_UI -> %lu; filter without NO_UI/hwnd -> %lu", d1, d2);
    EXPECT_EQ(d2, ERROR_INVALID_PARAMETER);
    CHECK(d1 != ERROR_INTERNET_FORCE_RETRY);
    a_close(r.hr); a_close(hc); a_close(hi); srv_stop(s);
}

TEST(auth_dlg_filter_on_200_passes_error_through) {
    REQUIRE(U(InternetErrorDlg));
    srv *s = srv_http(NULL, 0); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    /* filter on a 200 leaves dwError 0 untouched: not the credential path; record the result */
    DWORD d = dlg(NULL, r.hr, ERROR_SUCCESS, FLAGS_ERROR_UI_FILTER_FOR_ERRORS | FLAGS_ERROR_UI_FLAGS_NO_UI);
    t_note("filter on 200 with ERROR_SUCCESS: %lu", d);
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_dlg_flow_retry_after_setting_creds) {
    REQUIRE(U(InternetErrorDlg));
    /* the classic loop: send -> 401 -> InternetErrorDlg(NO_UI) -> caller sets creds -> resend */
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("loop", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/loop", NULL, NULL, NULL, T_INET_FRESH, 0);
    int rounds = 0; DWORD st = 0;
    for (; rounds < 3; rounds++) {
        if (!U(HttpSendRequestA)(hr, NULL, 0, NULL, 0)) break;
        st = a_status(hr);
        if (st != 401) break;
        char sink[64]; t_inet_read_all(hr, sink, sizeof sink, NULL);
        DWORD d = dlg(NULL, hr, ERROR_SUCCESS, FLAGS_ERROR_UI_FILTER_FOR_ERRORS | FLAGS_ERROR_UI_FLAGS_NO_UI);
        t_note("round %d: InternetErrorDlg -> %lu", rounds, d);
        U(InternetSetOptionA)(hr, INTERNET_OPTION_USERNAME, "loop", 4);
        U(InternetSetOptionA)(hr, INTERNET_OPTION_PASSWORD, "pw", 2);
    }
    EXPECT_EQ(st, 200);
    EXPECT_EQ(rounds, 1);
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}
