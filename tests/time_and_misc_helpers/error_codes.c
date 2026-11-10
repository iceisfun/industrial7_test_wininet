/* ERROR_INTERNET_* code values, the message table in wininet.dll, and GetLastError after well-understood failures.
 * VM_TIMEOUT: 180 */
#include "tm.h"
#include "srv.h"
#include "tnet.h"

typedef struct { DWORD code; const char *name; } errdef;
#define E(x) { x, #x }
static const errdef errs[] = {
    E(ERROR_INTERNET_OUT_OF_HANDLES), E(ERROR_INTERNET_TIMEOUT), E(ERROR_INTERNET_EXTENDED_ERROR),
    E(ERROR_INTERNET_INTERNAL_ERROR), E(ERROR_INTERNET_INVALID_URL), E(ERROR_INTERNET_UNRECOGNIZED_SCHEME),
    E(ERROR_INTERNET_NAME_NOT_RESOLVED), E(ERROR_INTERNET_PROTOCOL_NOT_FOUND), E(ERROR_INTERNET_INVALID_OPTION),
    E(ERROR_INTERNET_BAD_OPTION_LENGTH), E(ERROR_INTERNET_OPTION_NOT_SETTABLE), E(ERROR_INTERNET_SHUTDOWN),
    E(ERROR_INTERNET_INCORRECT_USER_NAME), E(ERROR_INTERNET_INCORRECT_PASSWORD), E(ERROR_INTERNET_LOGIN_FAILURE),
    E(ERROR_INTERNET_INVALID_OPERATION), E(ERROR_INTERNET_OPERATION_CANCELLED), E(ERROR_INTERNET_INCORRECT_HANDLE_TYPE),
    E(ERROR_INTERNET_INCORRECT_HANDLE_STATE), E(ERROR_INTERNET_NOT_PROXY_REQUEST), E(ERROR_INTERNET_REGISTRY_VALUE_NOT_FOUND),
    E(ERROR_INTERNET_BAD_REGISTRY_PARAMETER), E(ERROR_INTERNET_NO_DIRECT_ACCESS), E(ERROR_INTERNET_NO_CONTEXT),
    E(ERROR_INTERNET_NO_CALLBACK), E(ERROR_INTERNET_REQUEST_PENDING), E(ERROR_INTERNET_INCORRECT_FORMAT),
    E(ERROR_INTERNET_ITEM_NOT_FOUND), E(ERROR_INTERNET_CANNOT_CONNECT), E(ERROR_INTERNET_CONNECTION_ABORTED),
    E(ERROR_INTERNET_CONNECTION_RESET), E(ERROR_INTERNET_FORCE_RETRY), E(ERROR_INTERNET_INVALID_PROXY_REQUEST),
    E(ERROR_INTERNET_NEED_UI), E(ERROR_INTERNET_HANDLE_EXISTS), E(ERROR_INTERNET_SEC_CERT_DATE_INVALID),
    E(ERROR_INTERNET_SEC_CERT_CN_INVALID), E(ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR), E(ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR),
    E(ERROR_INTERNET_MIXED_SECURITY), E(ERROR_INTERNET_CHG_POST_IS_NON_SECURE), E(ERROR_INTERNET_POST_IS_NON_SECURE),
    E(ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED), E(ERROR_INTERNET_INVALID_CA), E(ERROR_INTERNET_CLIENT_AUTH_NOT_SETUP),
    E(ERROR_INTERNET_ASYNC_THREAD_FAILED), E(ERROR_INTERNET_REDIRECT_SCHEME_CHANGE), E(ERROR_INTERNET_DIALOG_PENDING),
    E(ERROR_INTERNET_RETRY_DIALOG), E(ERROR_INTERNET_HTTPS_HTTP_SUBMIT_REDIR), E(ERROR_INTERNET_INSERT_CDROM),
    E(ERROR_INTERNET_FORTEZZA_LOGIN_NEEDED), E(ERROR_INTERNET_SEC_CERT_ERRORS), E(ERROR_INTERNET_SEC_CERT_NO_REV),
    E(ERROR_INTERNET_SEC_CERT_REV_FAILED), E(ERROR_FTP_TRANSFER_IN_PROGRESS), E(ERROR_FTP_DROPPED),
    E(ERROR_FTP_NO_PASSIVE_MODE), E(ERROR_GOPHER_PROTOCOL_ERROR), E(ERROR_GOPHER_NOT_FILE), E(ERROR_GOPHER_DATA_ERROR),
    E(ERROR_GOPHER_END_OF_DATA), E(ERROR_GOPHER_INVALID_LOCATOR), E(ERROR_GOPHER_INCORRECT_LOCATOR_TYPE),
    E(ERROR_GOPHER_NOT_GOPHER_PLUS), E(ERROR_GOPHER_ATTRIBUTE_NOT_FOUND), E(ERROR_GOPHER_UNKNOWN_LOCATOR),
    E(ERROR_HTTP_HEADER_NOT_FOUND), E(ERROR_HTTP_DOWNLEVEL_SERVER), E(ERROR_HTTP_INVALID_SERVER_RESPONSE),
    E(ERROR_HTTP_INVALID_HEADER), E(ERROR_HTTP_INVALID_QUERY_REQUEST), E(ERROR_HTTP_HEADER_ALREADY_EXISTS),
    E(ERROR_HTTP_REDIRECT_FAILED), E(ERROR_INTERNET_SECURITY_CHANNEL_ERROR), E(ERROR_INTERNET_UNABLE_TO_CACHE_FILE),
    E(ERROR_INTERNET_TCPIP_NOT_INSTALLED), E(ERROR_HTTP_NOT_REDIRECTED), E(ERROR_HTTP_COOKIE_NEEDS_CONFIRMATION),
    E(ERROR_HTTP_COOKIE_DECLINED), E(ERROR_INTERNET_DISCONNECTED), E(ERROR_INTERNET_SERVER_UNREACHABLE),
    E(ERROR_INTERNET_PROXY_SERVER_UNREACHABLE), E(ERROR_INTERNET_BAD_AUTO_PROXY_SCRIPT),
    E(ERROR_INTERNET_UNABLE_TO_DOWNLOAD_SCRIPT), E(ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION), E(ERROR_INTERNET_SEC_INVALID_CERT),
    E(ERROR_INTERNET_SEC_CERT_REVOKED), E(ERROR_INTERNET_FAILED_DUETOSECURITYCHECK), E(ERROR_INTERNET_NOT_INITIALIZED),
    E(ERROR_INTERNET_NEED_MSN_SSPI_PKG), E(ERROR_INTERNET_LOGIN_FAILURE_DISPLAY_ENTITY_BODY),
};

/* documented numeric values (SDK wininet.h) */
TEST(terr_code_values) {
    static const struct { DWORD code, want; } v[] = {
        { ERROR_INTERNET_OUT_OF_HANDLES, 12001 }, { ERROR_INTERNET_TIMEOUT, 12002 }, { ERROR_INTERNET_EXTENDED_ERROR, 12003 },
        { ERROR_INTERNET_INTERNAL_ERROR, 12004 }, { ERROR_INTERNET_INVALID_URL, 12005 }, { ERROR_INTERNET_UNRECOGNIZED_SCHEME, 12006 },
        { ERROR_INTERNET_NAME_NOT_RESOLVED, 12007 }, { ERROR_INTERNET_INVALID_OPTION, 12009 }, { ERROR_INTERNET_BAD_OPTION_LENGTH, 12010 },
        { ERROR_INTERNET_OPTION_NOT_SETTABLE, 12011 }, { ERROR_INTERNET_SHUTDOWN, 12012 }, { ERROR_INTERNET_LOGIN_FAILURE, 12015 },
        { ERROR_INTERNET_INVALID_OPERATION, 12016 }, { ERROR_INTERNET_OPERATION_CANCELLED, 12017 },
        { ERROR_INTERNET_INCORRECT_HANDLE_TYPE, 12018 }, { ERROR_INTERNET_INCORRECT_HANDLE_STATE, 12019 },
        { ERROR_INTERNET_ITEM_NOT_FOUND, 12028 }, { ERROR_INTERNET_CANNOT_CONNECT, 12029 }, { ERROR_INTERNET_CONNECTION_ABORTED, 12030 },
        { ERROR_INTERNET_CONNECTION_RESET, 12031 }, { ERROR_INTERNET_FORCE_RETRY, 12032 }, { ERROR_INTERNET_NEED_UI, 12034 },
        { ERROR_INTERNET_SEC_CERT_DATE_INVALID, 12037 }, { ERROR_INTERNET_SEC_CERT_CN_INVALID, 12038 },
        { ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR, 12039 }, { ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR, 12040 },
        { ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED, 12044 }, { ERROR_INTERNET_INVALID_CA, 12045 }, { ERROR_INTERNET_INSERT_CDROM, 12053 },
        { ERROR_INTERNET_SEC_CERT_ERRORS, 12055 }, { ERROR_INTERNET_SEC_CERT_REV_FAILED, 12057 },
        { ERROR_HTTP_HEADER_NOT_FOUND, 12150 }, { ERROR_HTTP_INVALID_SERVER_RESPONSE, 12152 }, { ERROR_HTTP_INVALID_HEADER, 12153 },
        { ERROR_HTTP_INVALID_QUERY_REQUEST, 12154 }, { ERROR_HTTP_HEADER_ALREADY_EXISTS, 12155 }, { ERROR_HTTP_REDIRECT_FAILED, 12156 },
        { ERROR_INTERNET_SECURITY_CHANNEL_ERROR, 12157 }, { ERROR_HTTP_COOKIE_NEEDS_CONFIRMATION, 12161 },
        { ERROR_HTTP_COOKIE_DECLINED, 12162 }, { ERROR_INTERNET_DISCONNECTED, 12163 }, { ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION, 12168 },
        { ERROR_INTERNET_SEC_INVALID_CERT, 12169 }, { ERROR_INTERNET_SEC_CERT_REVOKED, 12170 }, { ERROR_INTERNET_NOT_INITIALIZED, 12172 },
        { ERROR_INTERNET_LOGIN_FAILURE_DISPLAY_ENTITY_BODY, 12174 }, { INTERNET_ERROR_BASE, 12000 },
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) CHECKF(v[i].code == v[i].want, "%lu != %lu", v[i].code, v[i].want);
}

/* wininet.dll carries the message table for its own codes [K]: FormatMessage(FROM_HMODULE) */
static DWORD msg(DWORD code, char *buf, DWORD cap) {
    HMODULE h = t_module("wininet.dll");
    return FormatMessageA(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, h, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, cap, NULL);
}

TEST(terr_message_table_core_codes) {
    REQUIRE(t_module("wininet.dll"));
    static const DWORD core[] = { 12001, 12002, 12004, 12005, 12006, 12007, 12009, 12010, 12011, 12012, 12013, 12014, 12015,
                                  12016, 12017, 12018, 12019, 12028, 12029, 12030, 12031, 12037, 12038, 12044, 12045,
                                  12150, 12152, 12153, 12154, 12155, 12156, 12157 };
    for (size_t i = 0; i < sizeof core / sizeof core[0]; i++) {
        char buf[512] = "";
        DWORD n = msg(core[i], buf, sizeof buf);
        CHECKF(n > 0 && strlen(buf) == n, "no message for %lu (%lu)", core[i], GetLastError());
    }
}

TEST(terr_message_table_survey) {
    REQUIRE(t_module("wininet.dll"));
    int have = 0, missing = 0; char miss[1024] = ""; size_t o = 0;
    for (DWORD c = 12001; c <= 12185; c++) {
        char buf[512] = "";
        if (msg(c, buf, sizeof buf)) have++;
        else { missing++; if (o < sizeof miss - 8) o += snprintf(miss + o, sizeof miss - o, "%lu ", c); }
    }
    t_note("wininet message table 12001..12185: %d with text, %d without: %s", have, missing, miss);
    char b[512] = "";
    msg(ERROR_INTERNET_CANNOT_CONNECT, b, sizeof b);  t_note("12029: %s", b);
    msg(ERROR_INTERNET_EXTENDED_ERROR, b, sizeof b);  t_note("12003: %s", b);
    msg(ERROR_HTTP_HEADER_NOT_FOUND, b, sizeof b);    t_note("12150: %s", b);
    CHECK(have >= 60);
}

TEST(terr_message_table_not_for_win32_codes) {
    /* ordinary Win32 codes are not in wininet's table */
    REQUIRE(t_module("wininet.dll"));
    char buf[256];
    SET_ERR(0);
    DWORD n = msg(ERROR_FILE_NOT_FOUND, buf, sizeof buf);
    DWORD e = GetLastError();
    t_note("FormatMessage(wininet, 2) = %lu err %lu", n, e);
    CHECK(n == 0);
    EXPECT_EQ(e, ERROR_MR_MID_NOT_FOUND);
}

TEST(terr_names_helper_consistent) {
    for (size_t i = 0; i < sizeof errs / sizeof errs[0]; i++) {
        CHECK(errs[i].code >= 12000 && errs[i].code <= 12200);
        for (size_t j = i + 1; j < sizeof errs / sizeof errs[0]; j++) CHECKF(errs[i].code != errs[j].code, "%s == %s", errs[i].name, errs[j].name);
    }
}

/* ------------------------------------------------------------ GetLastError after failures with a fixed cause */
TEST(terr_crack_url_unrecognized_scheme) {
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA uc; memset(&uc, 0, sizeof uc); uc.dwStructSize = sizeof uc; uc.dwHostNameLength = 1;
    SET_ERR(0);
    CHECK(!U(InternetCrackUrlA)("nonsense", 0, 0, &uc));
    EXPECT_ERR(ERROR_INTERNET_UNRECOGNIZED_SCHEME);
}

TEST(terr_close_unmapped_handle) {
    REQUIRE(U(InternetCloseHandle));
    SET_ERR(0); CHECK(!U(InternetCloseHandle)((HINTERNET)(ULONG_PTR)0x7FFF0000)); EXPECT_ERR(ERROR_INVALID_HANDLE);
}

TEST(terr_close_twice) {
    REQUIRE(U(InternetCloseHandle));
    HINTERNET hi = t_inet_open("terr");
    CHECK(hi != NULL); if (!hi) return;
    CHECK(U(InternetCloseHandle)(hi));
    SET_ERR(0); CHECK(!U(InternetCloseHandle)(hi)); EXPECT_ERR(ERROR_INVALID_HANDLE);
}

TEST(terr_option_errors) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(InternetQueryOptionA));
    HINTERNET hi = t_inet_open("terro");
    CHECK(hi != NULL); if (!hi) return;
    DWORD v = 1000, len = 2;
    SET_ERR(0); CHECK(!U(InternetSetOptionA)(hi, 9999, &v, sizeof v));                    EXPECT_ERR(ERROR_INTERNET_INVALID_OPTION);
    SET_ERR(0); CHECK(!U(InternetSetOptionA)(hi, INTERNET_OPTION_CONNECT_TIMEOUT, &v, 2)); EXPECT_ERR(ERROR_INTERNET_BAD_OPTION_LENGTH);
    SET_ERR(0); CHECK(!U(InternetQueryOptionA)(hi, INTERNET_OPTION_CONNECT_TIMEOUT, &v, &len)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(len, 4);
    t_inet_close(hi);
}

TEST(terr_wrong_handle_type) {
    REQUIRE(U(HttpOpenRequestA)); REQUIRE(U(InternetConnectA));
    HINTERNET hi = t_inet_open("terrt");
    CHECK(hi != NULL); if (!hi) return;
    SET_ERR(0);
    HINTERNET hr = U(HttpOpenRequestA)(hi, "GET", "/", NULL, NULL, NULL, 0, 0);
    CHECK(hr == NULL); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (hc) {
        SET_ERR(0);
        HINTERNET h2 = U(InternetConnectA)(hc, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        DWORD e = GetLastError();
        t_note("InternetConnect on a connect handle: %p e=%lu", h2, e);
        CHECK(h2 == NULL); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        if (h2) U(InternetCloseHandle)(h2);
    }
    t_inet_close(hc); t_inet_close(hi);
}

TEST(terr_cannot_connect) {
    REQUIRE(U(InternetOpenUrlA));
    srv *s = srv_http(NULL, 0);
    if (!s) { t_skip("server unavailable"); return; }
    char url[128]; snprintf(url, sizeof url, "%s", srv_url(s, "/gone"));
    srv_stop(s);
    HINTERNET hi = t_inet_open("terrc");
    SET_ERR(0);
    HINTERNET hu = U(InternetOpenUrlA)(hi, url, NULL, 0, T_INET_FRESH, 0);
    DWORD e = GetLastError();
    CHECK(hu == NULL); EXPECT_EQ(e, ERROR_INTERNET_CANNOT_CONNECT);
    if (hu) U(InternetCloseHandle)(hu);
    t_inet_close(hi);
}

TEST(terr_header_not_found) {
    REQUIRE(U(HttpQueryInfoA));
    srv *s = srv_http(NULL, 0);
    if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("terrh");
    HINTERNET hu = hi ? U(InternetOpenUrlA)(hi, srv_url(s, "/h"), NULL, 0, T_INET_FRESH, 0) : NULL;
    CHECK(hu != NULL);
    if (hu) {
        char buf[64] = "X-I7-Missing"; DWORD n = sizeof buf;
        SET_ERR(0);
        CHECK(!U(HttpQueryInfoA)(hu, HTTP_QUERY_CUSTOM, buf, &n, NULL));
        EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
        U(InternetCloseHandle)(hu);
    }
    t_inet_close(hi); srv_stop(s);
}

TEST(terr_untrusted_certificate) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "x"), S_LOOP() };
    srv *s = srv_https(st, 3, SRV_CERT_LOCALHOST);
    if (!s) { t_skip("https server unavailable"); return; }
    HINTERNET hi = t_inet_open("terrs");
    SET_ERR(0);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/c"), NULL, 0, T_INET_FRESH, 0);
    DWORD e = GetLastError();
    CHECK(hu == NULL); EXPECT_EQ(e, ERROR_INTERNET_INVALID_CA);       /* 04 F8, measured */
    if (hu) U(InternetCloseHandle)(hu);
    t_inet_close(hi); srv_stop(s);
}

TEST(terr_cookie_not_found) {
    REQUIRE(U(InternetGetCookieA));
    char buf[64]; DWORD n = sizeof buf;
    SET_ERR(0);
    CHECK(!U(InternetGetCookieA)(t_uniq_cookie_url("none"), NULL, buf, &n));
    EXPECT_ERR(ERROR_NO_MORE_ITEMS);
}

TEST(terr_errname_table_matches_formatmessage) {
    /* every code in the table should have a message on Win10 except the retired Gopher ones (recorded) */
    REQUIRE(t_module("wininet.dll"));
    int none = 0;
    for (size_t i = 0; i < sizeof errs / sizeof errs[0]; i++) {
        char buf[512] = "";
        if (!msg(errs[i].code, buf, sizeof buf)) { t_note("no message: %s (%lu)", errs[i].name, errs[i].code); none++; }
    }
    t_note("%d of %d table codes have no message text", none, (int)(sizeof errs / sizeof errs[0]));
}
