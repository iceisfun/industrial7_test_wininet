/* tnet.c - see tnet.h. All wininet calls go through U() (GetProcAddress); nothing is linked. */
#include "tnet.h"
#include "modules.h"
#include <wininet.h>
#include <stdlib.h>
#include <ctype.h>
#ifndef ERROR_INTERNET_DECODING_FAILED
#define ERROR_INTERNET_DECODING_FAILED 12175
#endif

_Static_assert(T_INET_FRESH == (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE |
                                INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES), "T_INET_FRESH");

static CRITICAL_SECTION g_cs; static INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK once_fn(PINIT_ONCE o, PVOID p, PVOID *c);
static void lock(void) { InitOnceExecuteOnce(&g_once, once_fn, NULL, NULL); EnterCriticalSection(&g_cs); }
static void unlock(void) { LeaveCriticalSection(&g_cs); }

static char **g_cache; static int g_ncache;
static char **g_ck_url, **g_ck_name; static int g_nck;
static BOOL CALLBACK once_fn(PINIT_ONCE o, PVOID p, PVOID *c) { InitializeCriticalSection(&g_cs); atexit(t_net_cleanup); return TRUE; }

static DWORD reg_dword(const char *val, int *found) {
    DWORD v = 0, n = sizeof v;
    *found = RegGetValueA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", val, RRF_RT_REG_DWORD, NULL, &v, &n) == ERROR_SUCCESS;
    return v;
}
void t_net_prepare(void) {
    static volatile LONG done;
    if (InterlockedExchange(&done, 1)) return;
    lock(); unlock();
    int f1, f2, f3; DWORD pe = reg_dword("ProxyEnable", &f1), sp = reg_dword("SecureProtocols", &f2), cr = reg_dword("CertificateRevocation", &f3);
    char acu[8]; DWORD n = sizeof acu;
    int have_pac = RegGetValueA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "AutoConfigURL", RRF_RT_REG_SZ, NULL, acu, &n) != ERROR_FILE_NOT_FOUND;
    BYTE dcs[16]; DWORD dn = sizeof dcs; int autodetect = -1;
    if (RegGetValueA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections", "DefaultConnectionSettings", RRF_RT_REG_BINARY, NULL, dcs, &dn) == ERROR_MORE_DATA || dn >= 9)
        autodetect = dn >= 9 ? !!(dcs[8] & 8) : -1;
    t_note("net env: ProxyEnable=%s%lu AutoConfigURL=%s autodetect=%d SecureProtocols=%s0x%lx CertificateRevocation=%s%lu (tests use DIRECT)",
           f1 ? "" : "(unset)", pe, have_pac ? "set" : "unset", autodetect, f2 ? "" : "(unset)", sp, f3 ? "" : "(unset)", cr);
}

void *t_inet_open_ex(const char *agent, DWORD access, DWORD flags, DWORD to) {
    if (!U(InternetOpenA)) return NULL;
    HINTERNET h = U(InternetOpenA)(agent ? agent : "wininet_test", access, NULL, NULL, flags);
    if (h && to && U(InternetSetOptionA)) {
        U(InternetSetOptionA)(h, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
        U(InternetSetOptionA)(h, INTERNET_OPTION_SEND_TIMEOUT, &to, sizeof to);
        U(InternetSetOptionA)(h, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
    }
    return h;
}
void *t_inet_open(const char *agent) { t_net_prepare(); return t_inet_open_ex(agent, INTERNET_OPEN_TYPE_DIRECT, 0, 5000); }
void t_inet_close(void *h) { if (h && U(InternetCloseHandle)) U(InternetCloseHandle)(h); }

size_t t_inet_read_all(void *h, char *buf, size_t cap, int *ok) {
    size_t n = 0; int good = 1; char sink[4096];
    for (int guard = 0; guard < 100000; guard++) {
        DWORD rd = 0; char *dst = n + 1 < cap ? buf + n : sink; DWORD want = n + 1 < cap ? (DWORD)(cap - 1 - n) : sizeof sink;
        if (want > 65536) want = 65536;
        if (!U(InternetReadFile)(h, dst, want, &rd)) { good = 0; break; }
        if (!rd) break;
        if (dst != sink) n += rd;
    }
    if (cap) buf[n < cap ? n : cap - 1] = 0;
    if (ok) *ok = good;
    return n;
}

int t_http_get(void *session, const char *url, const char *hdrs, DWORD flags, char *body, size_t cap, size_t *len, DWORD *err) {
    if (len) *len = 0; if (err) *err = 0; if (body && cap) body[0] = 0;
    HINTERNET hu = U(InternetOpenUrlA)(session, url, hdrs, hdrs ? (DWORD)-1 : 0, flags, 0);
    if (!hu) { if (err) *err = GetLastError(); return 0; }
    DWORD st = 0, l = sizeof st;
    if (!U(HttpQueryInfoA)(hu, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL)) { if (err) *err = GetLastError(); st = 0; }
    char tmp[1]; size_t n = t_inet_read_all(hu, body && cap ? body : tmp, body && cap ? cap : 1, NULL);
    if (len) *len = n;
    U(InternetCloseHandle)(hu);
    return (int)st;
}

int t_https_secflags(void *hreq, DWORD add) {
    DWORD f = 0, l = sizeof f;
    U(InternetQueryOptionA)(hreq, INTERNET_OPTION_SECURITY_FLAGS, &f, &l);
    f |= add;
    return U(InternetSetOptionA)(hreq, INTERNET_OPTION_SECURITY_FLAGS, &f, sizeof f);
}

const char *t_inet_errname(DWORD e) {
    static const struct { DWORD e; const char *n; } t[] = {
        { ERROR_FTP_DROPPED, "ERROR_FTP_DROPPED" }, { ERROR_FTP_NO_PASSIVE_MODE, "ERROR_FTP_NO_PASSIVE_MODE" },
        { ERROR_FTP_TRANSFER_IN_PROGRESS, "ERROR_FTP_TRANSFER_IN_PROGRESS" }, { ERROR_HTTP_COOKIE_DECLINED, "ERROR_HTTP_COOKIE_DECLINED" },
        { ERROR_HTTP_COOKIE_NEEDS_CONFIRMATION, "ERROR_HTTP_COOKIE_NEEDS_CONFIRMATION" }, { ERROR_HTTP_DOWNLEVEL_SERVER, "ERROR_HTTP_DOWNLEVEL_SERVER" },
        { ERROR_HTTP_HEADER_ALREADY_EXISTS, "ERROR_HTTP_HEADER_ALREADY_EXISTS" }, { ERROR_HTTP_HEADER_NOT_FOUND, "ERROR_HTTP_HEADER_NOT_FOUND" },
        { ERROR_HTTP_INVALID_HEADER, "ERROR_HTTP_INVALID_HEADER" }, { ERROR_HTTP_INVALID_QUERY_REQUEST, "ERROR_HTTP_INVALID_QUERY_REQUEST" },
        { ERROR_HTTP_INVALID_SERVER_RESPONSE, "ERROR_HTTP_INVALID_SERVER_RESPONSE" }, { ERROR_HTTP_NOT_REDIRECTED, "ERROR_HTTP_NOT_REDIRECTED" },
        { ERROR_HTTP_REDIRECT_FAILED, "ERROR_HTTP_REDIRECT_FAILED" }, { ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION, "ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION" },
        { ERROR_INTERNET_ASYNC_THREAD_FAILED, "ERROR_INTERNET_ASYNC_THREAD_FAILED" }, { ERROR_INTERNET_BAD_AUTO_PROXY_SCRIPT, "ERROR_INTERNET_BAD_AUTO_PROXY_SCRIPT" },
        { ERROR_INTERNET_BAD_OPTION_LENGTH, "ERROR_INTERNET_BAD_OPTION_LENGTH" }, { ERROR_INTERNET_BAD_REGISTRY_PARAMETER, "ERROR_INTERNET_BAD_REGISTRY_PARAMETER" },
        { ERROR_INTERNET_CANNOT_CONNECT, "ERROR_INTERNET_CANNOT_CONNECT" }, { ERROR_INTERNET_CHG_POST_IS_NON_SECURE, "ERROR_INTERNET_CHG_POST_IS_NON_SECURE" },
        { ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED, "ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED" }, { ERROR_INTERNET_CLIENT_AUTH_NOT_SETUP, "ERROR_INTERNET_CLIENT_AUTH_NOT_SETUP" },
        { ERROR_INTERNET_CONNECTION_ABORTED, "ERROR_INTERNET_CONNECTION_ABORTED" }, { ERROR_INTERNET_CONNECTION_RESET, "ERROR_INTERNET_CONNECTION_RESET" },
        { ERROR_INTERNET_DIALOG_PENDING, "ERROR_INTERNET_DIALOG_PENDING" }, { ERROR_INTERNET_DISCONNECTED, "ERROR_INTERNET_DISCONNECTED" },
        { ERROR_INTERNET_EXTENDED_ERROR, "ERROR_INTERNET_EXTENDED_ERROR" }, { ERROR_INTERNET_FAILED_DUETOSECURITYCHECK, "ERROR_INTERNET_FAILED_DUETOSECURITYCHECK" },
        { ERROR_INTERNET_FORCE_RETRY, "ERROR_INTERNET_FORCE_RETRY" }, { ERROR_INTERNET_FORTEZZA_LOGIN_NEEDED, "ERROR_INTERNET_FORTEZZA_LOGIN_NEEDED" },
        { ERROR_INTERNET_HANDLE_EXISTS, "ERROR_INTERNET_HANDLE_EXISTS" }, { ERROR_INTERNET_HTTPS_HTTP_SUBMIT_REDIR, "ERROR_INTERNET_HTTPS_HTTP_SUBMIT_REDIR" },
        { ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR, "ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR" }, { ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR, "ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR" },
        { ERROR_INTERNET_INCORRECT_FORMAT, "ERROR_INTERNET_INCORRECT_FORMAT" }, { ERROR_INTERNET_INCORRECT_HANDLE_STATE, "ERROR_INTERNET_INCORRECT_HANDLE_STATE" },
        { ERROR_INTERNET_INCORRECT_HANDLE_TYPE, "ERROR_INTERNET_INCORRECT_HANDLE_TYPE" }, { ERROR_INTERNET_INCORRECT_PASSWORD, "ERROR_INTERNET_INCORRECT_PASSWORD" },
        { ERROR_INTERNET_INCORRECT_USER_NAME, "ERROR_INTERNET_INCORRECT_USER_NAME" }, { ERROR_INTERNET_INSERT_CDROM, "ERROR_INTERNET_INSERT_CDROM" },
        { ERROR_INTERNET_INTERNAL_ERROR, "ERROR_INTERNET_INTERNAL_ERROR" }, { ERROR_INTERNET_INVALID_CA, "ERROR_INTERNET_INVALID_CA" },
        { ERROR_INTERNET_INVALID_OPERATION, "ERROR_INTERNET_INVALID_OPERATION" }, { ERROR_INTERNET_INVALID_OPTION, "ERROR_INTERNET_INVALID_OPTION" },
        { ERROR_INTERNET_INVALID_PROXY_REQUEST, "ERROR_INTERNET_INVALID_PROXY_REQUEST" }, { ERROR_INTERNET_INVALID_URL, "ERROR_INTERNET_INVALID_URL" },
        { ERROR_INTERNET_ITEM_NOT_FOUND, "ERROR_INTERNET_ITEM_NOT_FOUND" }, { ERROR_INTERNET_LOGIN_FAILURE, "ERROR_INTERNET_LOGIN_FAILURE" },
        { ERROR_INTERNET_LOGIN_FAILURE_DISPLAY_ENTITY_BODY, "ERROR_INTERNET_LOGIN_FAILURE_DISPLAY_ENTITY_BODY" }, { ERROR_INTERNET_MIXED_SECURITY, "ERROR_INTERNET_MIXED_SECURITY" },
        { ERROR_INTERNET_NAME_NOT_RESOLVED, "ERROR_INTERNET_NAME_NOT_RESOLVED" }, { ERROR_INTERNET_NEED_MSN_SSPI_PKG, "ERROR_INTERNET_NEED_MSN_SSPI_PKG" },
        { ERROR_INTERNET_NEED_UI, "ERROR_INTERNET_NEED_UI" }, { ERROR_INTERNET_NO_CALLBACK, "ERROR_INTERNET_NO_CALLBACK" },
        { ERROR_INTERNET_NO_CONTEXT, "ERROR_INTERNET_NO_CONTEXT" }, { ERROR_INTERNET_NO_DIRECT_ACCESS, "ERROR_INTERNET_NO_DIRECT_ACCESS" },
        { ERROR_INTERNET_NOT_INITIALIZED, "ERROR_INTERNET_NOT_INITIALIZED" }, { ERROR_INTERNET_NOT_PROXY_REQUEST, "ERROR_INTERNET_NOT_PROXY_REQUEST" },
        { ERROR_INTERNET_OPERATION_CANCELLED, "ERROR_INTERNET_OPERATION_CANCELLED" }, { ERROR_INTERNET_OPTION_NOT_SETTABLE, "ERROR_INTERNET_OPTION_NOT_SETTABLE" },
        { ERROR_INTERNET_OUT_OF_HANDLES, "ERROR_INTERNET_OUT_OF_HANDLES" }, { ERROR_INTERNET_POST_IS_NON_SECURE, "ERROR_INTERNET_POST_IS_NON_SECURE" },
        { ERROR_INTERNET_PROTOCOL_NOT_FOUND, "ERROR_INTERNET_PROTOCOL_NOT_FOUND" }, { ERROR_INTERNET_PROXY_SERVER_UNREACHABLE, "ERROR_INTERNET_PROXY_SERVER_UNREACHABLE" },
        { ERROR_INTERNET_REDIRECT_SCHEME_CHANGE, "ERROR_INTERNET_REDIRECT_SCHEME_CHANGE" }, { ERROR_INTERNET_REGISTRY_VALUE_NOT_FOUND, "ERROR_INTERNET_REGISTRY_VALUE_NOT_FOUND" },
        { ERROR_INTERNET_REQUEST_PENDING, "ERROR_INTERNET_REQUEST_PENDING" }, { ERROR_INTERNET_RETRY_DIALOG, "ERROR_INTERNET_RETRY_DIALOG" },
        { ERROR_INTERNET_SEC_CERT_CN_INVALID, "ERROR_INTERNET_SEC_CERT_CN_INVALID" }, { ERROR_INTERNET_SEC_CERT_DATE_INVALID, "ERROR_INTERNET_SEC_CERT_DATE_INVALID" },
        { ERROR_INTERNET_SEC_CERT_ERRORS, "ERROR_INTERNET_SEC_CERT_ERRORS" }, { ERROR_INTERNET_SEC_CERT_NO_REV, "ERROR_INTERNET_SEC_CERT_NO_REV" },
        { ERROR_INTERNET_SEC_CERT_REV_FAILED, "ERROR_INTERNET_SEC_CERT_REV_FAILED" }, { ERROR_INTERNET_SEC_CERT_REVOKED, "ERROR_INTERNET_SEC_CERT_REVOKED" },
        { ERROR_INTERNET_SEC_INVALID_CERT, "ERROR_INTERNET_SEC_INVALID_CERT" }, { ERROR_INTERNET_SECURITY_CHANNEL_ERROR, "ERROR_INTERNET_SECURITY_CHANNEL_ERROR" },
        { ERROR_INTERNET_SERVER_UNREACHABLE, "ERROR_INTERNET_SERVER_UNREACHABLE" }, { ERROR_INTERNET_SHUTDOWN, "ERROR_INTERNET_SHUTDOWN" },
        { ERROR_INTERNET_TCPIP_NOT_INSTALLED, "ERROR_INTERNET_TCPIP_NOT_INSTALLED" }, { ERROR_INTERNET_TIMEOUT, "ERROR_INTERNET_TIMEOUT" },
        { ERROR_INTERNET_UNABLE_TO_CACHE_FILE, "ERROR_INTERNET_UNABLE_TO_CACHE_FILE" }, { ERROR_INTERNET_UNABLE_TO_DOWNLOAD_SCRIPT, "ERROR_INTERNET_UNABLE_TO_DOWNLOAD_SCRIPT" },
        { ERROR_INTERNET_UNRECOGNIZED_SCHEME, "ERROR_INTERNET_UNRECOGNIZED_SCHEME" }, { ERROR_INTERNET_DECODING_FAILED, "ERROR_INTERNET_DECODING_FAILED" },
        { 0, NULL } };
    for (int i = 0; t[i].n; i++) if (t[i].e == e) return t[i].n;
    return "?";
}

/* ------------------------------------------------------------------ unique names */
static char g_ub[16][256]; static volatile LONG g_ui, g_seq;
static char *ubuf(void) { return g_ub[InterlockedIncrement(&g_ui) & 15]; }
const char *t_uniq(const char *tag) {
    char *b = ubuf(); snprintf(b, 256, "%s_%lu_%ld_%s", T_TMP_PREFIX, GetCurrentProcessId(), InterlockedIncrement(&g_seq), tag ? tag : "x");
    return b;
}
const char *t_uniq_host(const char *tag) {
    char *b = ubuf(), clean[64]; size_t k = 0;
    for (const char *p = tag ? tag : ""; *p && k < sizeof clean - 1; p++) if (isalnum((unsigned char)*p)) clean[k++] = (char)tolower((unsigned char)*p);
    clean[k] = 0;
    snprintf(b, 256, "%s%lun%ld%s.i7test.example", T_TMP_PREFIX, GetCurrentProcessId(), InterlockedIncrement(&g_seq), clean);
    return b;
}
const char *t_uniq_cookie_url(const char *tag) { char *b = ubuf(); snprintf(b, 256, "http://%s/%s/", t_uniq_host(tag), tag ? tag : "c"); return b; }
const char *t_uniq_cache_url(const char *tag) { char *b = ubuf(); snprintf(b, 256, "http://%s/%s.txt", t_uniq_host(tag), tag ? tag : "c"); t_cache_track(b); return b; }

void t_cache_track(const char *url) {
    lock();
    g_cache = realloc(g_cache, (g_ncache + 1) * sizeof *g_cache); g_cache[g_ncache++] = _strdup(url);
    unlock();
}
void t_cookie_track(const char *url, const char *name) {
    lock();
    g_ck_url = realloc(g_ck_url, (g_nck + 1) * sizeof *g_ck_url); g_ck_name = realloc(g_ck_name, (g_nck + 1) * sizeof *g_ck_name);
    g_ck_url[g_nck] = _strdup(url); g_ck_name[g_nck] = _strdup(name); g_nck++;
    unlock();
}
void t_net_cleanup(void) {
    lock();
    for (int i = 0; i < g_ncache; i++) {
        if (U(DeleteUrlCacheEntryA)) U(DeleteUrlCacheEntryA)(g_cache[i]);   /* ERROR_FILE_NOT_FOUND is fine */
        free(g_cache[i]);
    }
    free(g_cache); g_cache = NULL; g_ncache = 0;
    for (int i = 0; i < g_nck; i++) {
        if (U(InternetSetCookieA)) U(InternetSetCookieA)(g_ck_url[i], g_ck_name[i], "x; expires=Thu, 01-Jan-1970 00:00:01 GMT");
        free(g_ck_url[i]); free(g_ck_name[i]);
    }
    free(g_ck_url); free(g_ck_name); g_ck_url = g_ck_name = NULL; g_nck = 0;
    unlock();
}
