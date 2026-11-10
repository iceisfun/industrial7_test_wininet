/* proto.c - environment probe for the wininet corpus server/VM design (docs/research/04_server_and_vm_design.md).
 * NOT a test area: a one-off measurement program for the Win10 VM. Scaffolding is linked directly here
 * (ws2_32, crypt32, secur32, wininet, winhttp, ncrypt); the real corpus library resolves at runtime.
 *
 *   proto.exe                 run every probe, print "P <key> <value>" lines
 *   proto.exe --spew N [b]    print N bytes of 64-byte lines to stdout (b = fully buffered), then "P spew_ms <ms>"
 *   proto.exe --com1 N        open \\.\COM1 itself and write N bytes in 4 KB chunks, then report the time on COM1
 *
 * All servers bind 127.0.0.1 (or ::1) on an ephemeral port, live at most a few seconds, and are joined.
 * Every network wait is bounded. No registry/proxy/zone state is changed. Key containers are deleted. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS 1
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <sspi.h>
#include <schannel.h>
#include <wininet.h>
/* winhttp.h and wininet.h cannot share a translation unit (URL_COMPONENTS etc. clash): declare what we use. */
typedef struct { BOOL fAutoDetect; LPWSTR lpszAutoConfigUrl; LPWSTR lpszProxy; LPWSTR lpszProxyBypass; } WINHTTP_CURRENT_USER_IE_PROXY_CONFIG;
BOOL WINAPI WinHttpGetIEProxyConfigForCurrentUser(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *);
BOOL WINAPI WinHttpDetectAutoProxyConfigUrl(DWORD, LPWSTR *);
#define WINHTTP_AUTO_DETECT_TYPE_DHCP 1
#define WINHTTP_AUTO_DETECT_TYPE_DNS_A 2
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef INTERNET_OPTION_SECURITY_CONNECTION_INFO
#define INTERNET_OPTION_SECURITY_CONNECTION_INFO 66
typedef struct { DWORD dwSize; BOOL fSecure; DWORD dwProtocol; ALG_ID aiCipher; DWORD dwCipherStrength;
                 ALG_ID aiHash; DWORD dwHashStrength; ALG_ID aiExch; DWORD dwExchStrength; } INTERNET_SECURITY_CONNECTION_INFO;
#endif

static LARGE_INTEGER g_qf;
static double now_ms(void) { LARGE_INTEGER c; QueryPerformanceCounter(&c); return c.QuadPart * 1000.0 / g_qf.QuadPart; }
#define P(...) do { printf("P "); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while (0)

static void escape_print(const char *key, const char *buf, int n) {
    /* request bytes as one line: \r\n -> "|" so the raw wire request is readable in serial.log */
    char out[8192]; int o = 0;
    for (int i = 0; i < n && o < (int)sizeof out - 8; i++) {
        unsigned char c = buf[i];
        if (c == '\r') continue;
        if (c == '\n') { out[o++] = '|'; continue; }
        if (c < 32 || c > 126) o += snprintf(out + o, 8, "\\x%02x", c); else out[o++] = c;
    }
    out[o] = 0; P("%s %s", key, out);
}

/* ------------------------------------------------------------------ loopback */
static SOCKET listen_on(int af, unsigned short *port) {
    SOCKET s = socket(af, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return s;
    struct sockaddr_storage ss; int len; memset(&ss, 0, sizeof ss);
    if (af == AF_INET) { struct sockaddr_in *a = (void *)&ss; a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(INADDR_LOOPBACK); len = sizeof *a; }
    else { struct sockaddr_in6 *a = (void *)&ss; a->sin6_family = AF_INET6; a->sin6_addr = in6addr_loopback; len = sizeof *a; }
    BOOL excl = TRUE; setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&excl, sizeof excl);
    if (bind(s, (void *)&ss, len) || listen(s, 16)) { closesocket(s); return INVALID_SOCKET; }
    len = sizeof ss; getsockname(s, (void *)&ss, &len);
    *port = ntohs(af == AF_INET ? ((struct sockaddr_in *)&ss)->sin_port : ((struct sockaddr_in6 *)&ss)->sin6_port);
    return s;
}
static void set_timeouts(SOCKET s, DWORD ms) { setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, sizeof ms); setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&ms, sizeof ms); }
/* accept with a bounded wait */
static SOCKET accept_wait(SOCKET l, DWORD ms) {
    fd_set f; FD_ZERO(&f); FD_SET(l, &f); struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    if (select(0, &f, NULL, NULL, &tv) != 1) return INVALID_SOCKET;
    return accept(l, NULL, NULL);
}

static void probe_loopback(int af, const char *tag) {
    unsigned short port = 0; double t0 = now_ms();
    SOCKET l = listen_on(af, &port);
    if (l == INVALID_SOCKET) { P("%s_listen FAIL wsa=%d", tag, WSAGetLastError()); return; }
    SOCKET c = socket(af, SOCK_STREAM, IPPROTO_TCP); set_timeouts(c, 3000);
    struct sockaddr_storage ss; int len; memset(&ss, 0, sizeof ss);
    if (af == AF_INET) { struct sockaddr_in *a = (void *)&ss; a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(INADDR_LOOPBACK); a->sin_port = htons(port); len = sizeof *a; }
    else { struct sockaddr_in6 *a = (void *)&ss; a->sin6_family = AF_INET6; a->sin6_addr = in6addr_loopback; a->sin6_port = htons(port); len = sizeof *a; }
    int cr = connect(c, (void *)&ss, len);
    SOCKET a = accept_wait(l, 3000);
    char buf[16] = {0}; int ok = 0;
    if (!cr && a != INVALID_SOCKET) { set_timeouts(a, 3000); send(c, "ping", 4, 0); ok = recv(a, buf, sizeof buf, 0) == 4 && !memcmp(buf, "ping", 4); }
    P("%s port=%u connect=%d accept=%s echo=%s ms=%.1f", tag, port, cr ? WSAGetLastError() : 0, a == INVALID_SOCKET ? "no" : "yes", ok ? "ok" : "FAIL", now_ms() - t0);
    if (a != INVALID_SOCKET) closesocket(a); closesocket(c); closesocket(l);
}

static void probe_resolve(const char *host) {
    struct addrinfo hints = {0}, *res = NULL, *p; hints.ai_socktype = SOCK_STREAM;
    double t0 = now_ms(); int r = getaddrinfo(host, "80", &hints, &res); double dt = now_ms() - t0;
    char list[512] = ""; int o = 0;
    for (p = res; p && o < 400; p = p->ai_next) {
        char h[64] = "?"; getnameinfo(p->ai_addr, (int)p->ai_addrlen, h, sizeof h, NULL, 0, NI_NUMERICHOST);
        o += snprintf(list + o, sizeof list - o, "%s,", h);
    }
    P("resolve %s rc=%d ms=%.1f addrs=%s", host, r, dt, list);
    if (res) freeaddrinfo(res);
}

/* ------------------------------------------------------------------ HTTP server (thread per connection) */
typedef struct server server;
struct server {
    SOCKET l; unsigned short port; int af;
    volatile LONG stop; HANDLE thr;
    /* TLS */
    int tls; PCCERT_CONTEXT cert; CredHandle cred; int have_cred;
    /* recorder */
    CRITICAL_SECTION cs; char rec[16384]; int nrec; int nconn; char tlslog[1024];
};
typedef struct { server *s; SOCKET c; } conn_arg;

static const char RESP[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";

static void rec_add(server *s, const char *b, int n) {
    EnterCriticalSection(&s->cs);
    if (s->nrec + n + 2 < (int)sizeof s->rec) { memcpy(s->rec + s->nrec, b, n); s->nrec += n; s->rec[s->nrec++] = '#'; }
    LeaveCriticalSection(&s->cs);
}
static void tlslog(server *s, const char *fmt, ...) {
    char t[160]; va_list a; va_start(a, fmt); vsnprintf(t, sizeof t, fmt, a); va_end(a);
    EnterCriticalSection(&s->cs);
    size_t l = strlen(s->tlslog); if (l + strlen(t) + 2 < sizeof s->tlslog) { strcat(s->tlslog, t); strcat(s->tlslog, ";"); }
    LeaveCriticalSection(&s->cs);
}

/* read until \r\n\r\n; returns length or -1 */
static int read_head(SOCKET c, char *b, int cap) {
    int n = 0;
    while (n < cap - 1) {
        int r = recv(c, b + n, cap - 1 - n, 0); if (r <= 0) return n ? n : -1;
        n += r; b[n] = 0; if (strstr(b, "\r\n\r\n")) return n;
    }
    return n;
}

static int tls_send(server *s, CtxtHandle *ctx, SecPkgContext_StreamSizes *sz, SOCKET c, const char *data, int n) {
    char *buf = malloc(sz->cbHeader + n + sz->cbTrailer);
    memcpy(buf + sz->cbHeader, data, n);
    SecBuffer b[4] = { { sz->cbHeader, SECBUFFER_STREAM_HEADER, buf }, { n, SECBUFFER_DATA, buf + sz->cbHeader },
                       { sz->cbTrailer, SECBUFFER_STREAM_TRAILER, buf + sz->cbHeader + n }, { 0, SECBUFFER_EMPTY, NULL } };
    SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
    SECURITY_STATUS st = EncryptMessage(ctx, 0, &d, 0);
    int ok = st == SEC_E_OK && send(c, buf, b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer, 0) > 0;
    if (st != SEC_E_OK) tlslog(s, "Encrypt=0x%lx", st);
    free(buf); return ok;
}

static void serve_tls(server *s, SOCKET c) {
    CtxtHandle ctx; int have_ctx = 0; char in[32768]; int nin = 0; SECURITY_STATUS st = SEC_I_CONTINUE_NEEDED;
    DWORD req = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM, attr;
    int rounds = 0;
    while (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_INCOMPLETE_MESSAGE) {
        if (++rounds > 20) break;
        if (nin == 0 || st == SEC_E_INCOMPLETE_MESSAGE) { int r = recv(c, in + nin, sizeof in - nin, 0); if (r <= 0) { tlslog(s, "hs_recv=%d", r); goto out; } nin += r; }
        SecBuffer ib[2] = { { nin, SECBUFFER_TOKEN, in }, { 0, SECBUFFER_EMPTY, NULL } }; SecBufferDesc id = { SECBUFFER_VERSION, 2, ib };
        SecBuffer ob[1] = { { 0, SECBUFFER_TOKEN, NULL } }; SecBufferDesc od = { SECBUFFER_VERSION, 1, ob };
        st = AcceptSecurityContext(&s->cred, have_ctx ? &ctx : NULL, &id, req, 0, &ctx, &od, &attr, NULL);
        if (st == SEC_E_INCOMPLETE_MESSAGE) continue;
        have_ctx = 1;
        if (ob[0].cbBuffer && ob[0].pvBuffer) { send(c, ob[0].pvBuffer, ob[0].cbBuffer, 0); FreeContextBuffer(ob[0].pvBuffer); }
        if (ib[1].BufferType == SECBUFFER_EXTRA) { memmove(in, in + nin - ib[1].cbBuffer, ib[1].cbBuffer); nin = ib[1].cbBuffer; } else nin = 0;
        if (FAILED(st)) { tlslog(s, "ASC=0x%lx", st); goto out; }
    }
    if (st != SEC_E_OK) { tlslog(s, "hs_end=0x%lx", st); goto out; }
    SecPkgContext_ConnectionInfo ci; if (QueryContextAttributesA(&ctx, SECPKG_ATTR_CONNECTION_INFO, &ci) == SEC_E_OK) tlslog(s, "proto=0x%lx cipher=0x%x", ci.dwProtocol, ci.aiCipher);
    SecPkgContext_StreamSizes sz; QueryContextAttributesA(&ctx, SECPKG_ATTR_STREAM_SIZES, &sz);
    /* decrypt one request (may span records) */
    char plain[8192]; int np = 0;
    for (int guard = 0; guard < 20 && !strstr(plain, "\r\n\r\n"); guard++) {
        if (nin == 0 || st == SEC_E_INCOMPLETE_MESSAGE) { int r = recv(c, in + nin, sizeof in - nin, 0); if (r <= 0) { tlslog(s, "app_recv=%d", r); goto out; } nin += r; }
        SecBuffer b[4] = { { nin, SECBUFFER_DATA, in }, { 0, SECBUFFER_EMPTY, NULL }, { 0, SECBUFFER_EMPTY, NULL }, { 0, SECBUFFER_EMPTY, NULL } };
        SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
        st = DecryptMessage(&ctx, &d, 0, NULL);
        if (st == SEC_E_INCOMPLETE_MESSAGE) continue;
        if (st != SEC_E_OK) { tlslog(s, "Decrypt=0x%lx", st); goto out; }
        int extra = 0;
        for (int i = 0; i < 4; i++) {
            if (b[i].BufferType == SECBUFFER_DATA && np + (int)b[i].cbBuffer < (int)sizeof plain - 1) { memcpy(plain + np, b[i].pvBuffer, b[i].cbBuffer); np += b[i].cbBuffer; plain[np] = 0; }
            if (b[i].BufferType == SECBUFFER_EXTRA) { memmove(in, in + nin - b[i].cbBuffer, b[i].cbBuffer); extra = b[i].cbBuffer; }
        }
        nin = extra;
    }
    rec_add(s, plain, np);
    tls_send(s, &ctx, &sz, c, RESP, sizeof RESP - 1);
    /* close_notify */
    DWORD tok = SCHANNEL_SHUTDOWN; SecBuffer tb = { sizeof tok, SECBUFFER_TOKEN, &tok }; SecBufferDesc td = { SECBUFFER_VERSION, 1, &tb };
    if (ApplyControlToken(&ctx, &td) == SEC_E_OK) {
        SecBuffer ob[1] = { { 0, SECBUFFER_TOKEN, NULL } }; SecBufferDesc od = { SECBUFFER_VERSION, 1, ob };
        if (AcceptSecurityContext(&s->cred, &ctx, NULL, req, 0, NULL, &od, &attr, NULL) == SEC_E_OK && ob[0].pvBuffer) { send(c, ob[0].pvBuffer, ob[0].cbBuffer, 0); FreeContextBuffer(ob[0].pvBuffer); }
    }
out:
    if (have_ctx) DeleteSecurityContext(&ctx);
}

static DWORD WINAPI conn_thread(LPVOID p) {
    conn_arg *ca = p; server *s = ca->s; SOCKET c = ca->c; free(ca);
    set_timeouts(c, 5000);
    if (s->tls) serve_tls(s, c);
    else {
        char b[8192]; int n = read_head(c, b, sizeof b);
        if (n > 0) { rec_add(s, b, n); send(c, RESP, sizeof RESP - 1, 0); }
    }
    shutdown(c, SD_SEND); { char d[256]; int g = 0; while (g++ < 8 && recv(c, d, sizeof d, 0) > 0) ; }
    closesocket(c); return 0;
}

static DWORD WINAPI accept_thread(LPVOID p) {
    server *s = p; HANDLE kids[64]; int nk = 0;
    while (!s->stop && nk < 64) {
        SOCKET c = accept_wait(s->l, 100);
        if (c == INVALID_SOCKET) continue;
        InterlockedIncrement((LONG *)&s->nconn);
        conn_arg *ca = malloc(sizeof *ca); ca->s = s; ca->c = c;
        kids[nk++] = CreateThread(NULL, 0, conn_thread, ca, 0, NULL);
    }
    for (int i = 0; i < nk; i++) { if (WaitForSingleObject(kids[i], 8000) != WAIT_OBJECT_0) tlslog(s, "conn_thread_hang"); CloseHandle(kids[i]); }
    return 0;
}

static int server_start(server *s, int af, int tls) {
    memset(s, 0, sizeof *s); InitializeCriticalSection(&s->cs); s->af = af; s->tls = tls;
    s->l = listen_on(af, &s->port); if (s->l == INVALID_SOCKET) return 0;
    s->thr = CreateThread(NULL, 0, accept_thread, s, 0, NULL); return 1;
}
static double server_stop(server *s) {
    double t0 = now_ms(); s->stop = 1;
    DWORD w = WaitForSingleObject(s->thr, 15000);
    CloseHandle(s->thr); closesocket(s->l);
    if (w != WAIT_OBJECT_0) P("server_stop HANG");
    return now_ms() - t0;
}
static void server_take(server *s, char *out, int *n) { EnterCriticalSection(&s->cs); memcpy(out, s->rec, s->nrec); *n = s->nrec; s->nrec = 0; LeaveCriticalSection(&s->cs); }

/* ------------------------------------------------------------------ wininet client */
typedef struct { const char *tag; const char *url; DWORD access; DWORD secflags; DWORD open_flags; } fetch_req;

/* InternetOpen(access) -> InternetConnect -> HttpOpenRequest -> HttpSendRequest, with optional retry adding flags.
 * Prints error/time/status/body. Returns last error (0 on success). */
static DWORD fetch(const char *tag, const char *host, unsigned short port, int https, DWORD access, DWORD retry_flags[], int nretry) {
    double t0 = now_ms(); DWORD err = 0;
    HINTERNET hi = InternetOpenA("i7proto/1.0", access, NULL, NULL, 0);
    double t_open = now_ms() - t0;
    if (!hi) { P("%s InternetOpen FAIL %lu", tag, GetLastError()); return GetLastError(); }
    DWORD to = 5000; InternetSetOptionA(hi, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
    InternetSetOptionA(hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to); InternetSetOptionA(hi, INTERNET_OPTION_SEND_TIMEOUT, &to, sizeof to);
    HINTERNET hc = InternetConnectA(hi, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    DWORD rf = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | (https ? INTERNET_FLAG_SECURE : 0);
    HINTERNET hr = hc ? HttpOpenRequestA(hc, "GET", "/p", NULL, NULL, NULL, rf, 0) : NULL;
    if (!hr) { P("%s open FAIL %lu", tag, GetLastError()); InternetCloseHandle(hc); InternetCloseHandle(hi); return GetLastError(); }
    for (int attempt = 0; attempt <= nretry; attempt++) {
        if (attempt) {
            DWORD f = 0, l = sizeof f; InternetQueryOptionA(hr, INTERNET_OPTION_SECURITY_FLAGS, &f, &l);
            f |= retry_flags[attempt - 1];
            BOOL so = InternetSetOptionA(hr, INTERNET_OPTION_SECURITY_FLAGS, &f, sizeof f);
            P("%s set_secflags 0x%lx ok=%d err=%lu", tag, f, so, so ? 0 : GetLastError());
        }
        double ts = now_ms();
        BOOL ok = HttpSendRequestA(hr, NULL, 0, NULL, 0);
        err = ok ? 0 : GetLastError();
        DWORD sf = 0, l = sizeof sf; InternetQueryOptionA(hr, INTERNET_OPTION_SECURITY_FLAGS, &sf, &l);
        P("%s attempt=%d send=%d err=%lu ms=%.1f secflags=0x%lx open_ms=%.1f", tag, attempt, ok, err, now_ms() - ts, sf, t_open);
        if (https) {
            INTERNET_SECURITY_CONNECTION_INFO ci = { sizeof ci }; l = sizeof ci;
            if (InternetQueryOptionA(hr, INTERNET_OPTION_SECURITY_CONNECTION_INFO, &ci, &l)) P("%s conninfo secure=%d proto=0x%lx cipher=0x%x exch=0x%x", tag, ci.fSecure, ci.dwProtocol, ci.aiCipher, ci.aiExch);
            else P("%s conninfo err=%lu", tag, GetLastError());
            INTERNET_CERTIFICATE_INFO cinfo; memset(&cinfo, 0, sizeof cinfo); l = sizeof cinfo;
            if (InternetQueryOptionA(hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &cinfo, &l)) {
                P("%s certinfo subject=[%s] keysize=%lu", tag, cinfo.lpszSubjectInfo ? cinfo.lpszSubjectInfo : "(null)", cinfo.dwKeySize);
                LocalFree(cinfo.lpszSubjectInfo); LocalFree(cinfo.lpszIssuerInfo); LocalFree(cinfo.lpszProtocolName); LocalFree(cinfo.lpszSignatureAlgName); LocalFree(cinfo.lpszEncryptionAlgName);
            } else P("%s certinfo err=%lu", tag, GetLastError());
        }
        if (ok) {
            DWORD st = 0; l = sizeof st; HttpQueryInfoA(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL);
            char body[64] = {0}; DWORD rd = 0; InternetReadFile(hr, body, sizeof body - 1, &rd);
            P("%s status=%lu body=[%s] total_ms=%.1f", tag, st, body, now_ms() - t0);
            break;
        }
    }
    InternetCloseHandle(hr); InternetCloseHandle(hc); InternetCloseHandle(hi);
    return err;
}

/* simple InternetOpenUrl timing (for proxy/WPAD measurements) */
static void open_url_timed(const char *tag, DWORD access, const char *url) {
    double t0 = now_ms();
    HINTERNET hi = InternetOpenA("i7proto/1.0", access, NULL, NULL, 0);
    double t1 = now_ms();
    DWORD to = 5000; InternetSetOptionA(hi, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to); InternetSetOptionA(hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
    HINTERNET hu = InternetOpenUrlA(hi, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI, 0);
    DWORD err = hu ? 0 : GetLastError(); double t2 = now_ms();
    char body[32] = {0}; DWORD rd = 0; if (hu) InternetReadFile(hu, body, sizeof body - 1, &rd);
    P("%s open_ms=%.1f openurl_ms=%.1f err=%lu body=[%s]", tag, t1 - t0, t2 - t1, err, body);
    if (hu) InternetCloseHandle(hu); InternetCloseHandle(hi);
}

typedef struct { const char *tag; DWORD access; char url[128]; } bg_req;
static DWORD WINAPI bg_open_url(LPVOID p) { bg_req *r = p; open_url_timed(r->tag, r->access, r->url); return 0; }
/* run in a thread with an outer bound so a slow DNS/WPAD path cannot stall the boot */
static void open_url_bounded(const char *tag, DWORD access, const char *url, DWORD bound_ms) {
    bg_req *r = malloc(sizeof *r); r->tag = tag; r->access = access; snprintf(r->url, sizeof r->url, "%s", url); /* leaked on purpose if detached */
    double t0 = now_ms(); HANDLE h = CreateThread(NULL, 0, bg_open_url, r, 0, NULL);
    if (WaitForSingleObject(h, bound_ms) != WAIT_OBJECT_0) P("%s STILL_RUNNING after %.0f ms (left detached)", tag, now_ms() - t0);
    CloseHandle(h);
}

static void probe_proxy_config(void) {
    INTERNET_PER_CONN_OPTIONA o[3]; o[0].dwOption = INTERNET_PER_CONN_FLAGS; o[1].dwOption = INTERNET_PER_CONN_PROXY_BYPASS; o[2].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    INTERNET_PER_CONN_OPTION_LISTA l = { sizeof l, NULL, 3, 0, o }; DWORD n = sizeof l;
    if (InternetQueryOptionA(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &l, &n))
        P("perconn flags=0x%lx bypass=[%s] autoconfig=[%s]", o[0].Value.dwValue, o[1].Value.pszValue ? o[1].Value.pszValue : "", o[2].Value.pszValue ? o[2].Value.pszValue : "");
    else P("perconn err=%lu", GetLastError());
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG c = {0};
    if (WinHttpGetIEProxyConfigForCurrentUser(&c)) P("ieproxy autodetect=%d autoconfig=%d proxy=%d", c.fAutoDetect, c.lpszAutoConfigUrl != NULL, c.lpszProxy != NULL);
    else P("ieproxy err=%lu", GetLastError());
    SC_HANDLE m = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    const char *svcs[] = { "WinHttpAutoProxySvc", "mpssvc", "WinDefend", "Dnscache", "iphlpsvc", NULL };
    for (int i = 0; m && svcs[i]; i++) {
        SC_HANDLE h = OpenServiceA(m, svcs[i], SERVICE_QUERY_STATUS); SERVICE_STATUS ss = {0};
        if (h && QueryServiceStatus(h, &ss)) P("svc %s state=%lu", svcs[i], ss.dwCurrentState); else P("svc %s err=%lu", svcs[i], GetLastError());
        if (h) CloseServiceHandle(h);
    }
    if (m) CloseServiceHandle(m);
}

/* WPAD: time WinHttpDetectAutoProxyConfigUrl directly, bounded */
static DWORD WINAPI bg_detect(LPVOID p) {
    double t0 = now_ms(); LPWSTR u = NULL;
    BOOL ok = WinHttpDetectAutoProxyConfigUrl(WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A, &u);
    P("wpad_detect ok=%d err=%lu ms=%.1f", ok, ok ? 0 : GetLastError(), now_ms() - t0);
    if (u) GlobalFree(u); return 0;
}

/* ------------------------------------------------------------------ certificates */
typedef struct { PCCERT_CONTEXT cert; WCHAR container[96]; int cng; } tls_ident;

static int make_cert(tls_ident *id, int cng, int with_san, const char *cn) {
    memset(id, 0, sizeof *id); id->cng = cng;
    swprintf(id->container, 96, L"i7proto_%lu_%d_%d", GetCurrentProcessId(), cng, with_san);
    char x500[128]; snprintf(x500, sizeof x500, "CN=%s", cn);
    BYTE name[256]; DWORD nl = sizeof name;
    if (!CertStrToNameA(X509_ASN_ENCODING, x500, CERT_X500_NAME_STR, NULL, name, &nl, NULL)) { P("certstrtoname err=%lu", GetLastError()); return 0; }
    CERT_NAME_BLOB nb = { nl, name };
    CRYPT_KEY_PROV_INFO kpi = {0}; kpi.pwszContainerName = id->container;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hk = 0; HCRYPTPROV hp = 0; NCRYPT_PROV_HANDLE np = 0; NCRYPT_KEY_HANDLE nk = 0;
    if (cng) {
        SECURITY_STATUS s = NCryptOpenStorageProvider(&np, MS_KEY_STORAGE_PROVIDER, 0);
        if (!s) s = NCryptCreatePersistedKey(np, &nk, BCRYPT_RSA_ALGORITHM, id->container, 0, 0);
        DWORD bits = 2048; if (!s) s = NCryptSetProperty(nk, NCRYPT_LENGTH_PROPERTY, (BYTE *)&bits, sizeof bits, 0);
        if (!s) s = NCryptFinalizeKey(nk, 0);
        if (s) { P("ncrypt key err=0x%lx", s); return 0; }
        hk = nk; kpi.pwszProvName = MS_KEY_STORAGE_PROVIDER; kpi.dwProvType = 0; kpi.dwKeySpec = 0;
    } else {
        if (!CryptAcquireContextW(&hp, id->container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET)) { P("capi acquire err=0x%lx", GetLastError()); return 0; }
        HCRYPTKEY k; if (!CryptGenKey(hp, AT_KEYEXCHANGE, (2048 << 16), &k)) { P("capi genkey err=0x%lx", GetLastError()); return 0; }
        CryptDestroyKey(k);
        hk = hp; kpi.pwszProvName = MS_ENH_RSA_AES_PROV_W; kpi.dwProvType = PROV_RSA_AES; kpi.dwKeySpec = AT_KEYEXCHANGE;
    }
    CERT_EXTENSION ext[2]; int next = 0; BYTE sanbuf[256], ekubuf[64]; DWORD sanl = sizeof sanbuf, ekul = sizeof ekubuf;
    if (with_san) {
        CERT_ALT_NAME_ENTRY e[2]; BYTE ip[4] = { 127, 0, 0, 1 };
        e[0].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME; e[0].pwszDNSName = L"localhost";
        e[1].dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS; e[1].IPAddress.cbData = 4; e[1].IPAddress.pbData = ip;
        CERT_ALT_NAME_INFO an = { 2, e };
        if (CryptEncodeObject(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &an, sanbuf, &sanl)) { ext[next].pszObjId = szOID_SUBJECT_ALT_NAME2; ext[next].fCritical = FALSE; ext[next].Value.cbData = sanl; ext[next].Value.pbData = sanbuf; next++; }
        LPSTR eku[1] = { szOID_PKIX_KP_SERVER_AUTH }; CERT_ENHKEY_USAGE u = { 1, eku };
        if (CryptEncodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &u, ekubuf, &ekul)) { ext[next].pszObjId = szOID_ENHANCED_KEY_USAGE; ext[next].fCritical = FALSE; ext[next].Value.cbData = ekul; ext[next].Value.pbData = ekubuf; next++; }
    }
    CERT_EXTENSIONS exts = { next, ext };
    CRYPT_ALGORITHM_IDENTIFIER alg = { szOID_RSA_SHA256RSA };
    double t0 = now_ms();
    id->cert = CertCreateSelfSignCertificate(hk, &nb, 0, &kpi, &alg, NULL, NULL, next ? &exts : NULL);
    P("selfsign cng=%d san=%d cn=%s ok=%d err=0x%lx ms=%.1f", cng, with_san, cn, id->cert != NULL, id->cert ? 0 : GetLastError(), now_ms() - t0);
    if (nk) NCryptFreeObject(nk);
    if (np) NCryptFreeObject(np);
    if (hp) CryptReleaseContext(hp, 0);
    return id->cert != NULL;
}
static void free_cert(tls_ident *id) {
    if (id->cert) CertFreeCertificateContext(id->cert);
    if (id->cng) {
        NCRYPT_PROV_HANDLE np; NCRYPT_KEY_HANDLE nk;
        if (!NCryptOpenStorageProvider(&np, MS_KEY_STORAGE_PROVIDER, 0)) {
            if (!NCryptOpenKey(np, &nk, id->container, 0, 0)) P("key_delete cng rc=0x%lx", NCryptDeleteKey(nk, 0));
            NCryptFreeObject(np);
        }
    } else { HCRYPTPROV hp; P("key_delete capi ok=%d", CryptAcquireContextW(&hp, id->container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET)); }
}

static int acquire_server_cred(server *s, PCCERT_CONTEXT cert, int use_sch_credentials) {
    SECURITY_STATUS st; TimeStamp ts; double t0 = now_ms();
    if (use_sch_credentials) {
        SCH_CREDENTIALS sc = {0}; sc.dwVersion = SCH_CREDENTIALS_VERSION; sc.cCreds = 1; sc.paCred = &cert; sc.dwFlags = SCH_USE_STRONG_CRYPTO;
        st = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_INBOUND, NULL, &sc, NULL, NULL, &s->cred, &ts);
    } else {
        SCHANNEL_CRED sc = {0}; sc.dwVersion = SCHANNEL_CRED_VERSION; sc.cCreds = 1; sc.paCred = &cert;
        st = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_INBOUND, NULL, &sc, NULL, NULL, &s->cred, &ts);
    }
    P("acquire_inbound schcreds=%d st=0x%lx ms=%.1f", use_sch_credentials, st, now_ms() - t0);
    s->have_cred = st == SEC_E_OK; return s->have_cred;
}

static void dump_server(server *s, const char *tag) {
    char b[16384]; int n; server_take(s, b, &n); escape_print(tag, b, n);
    if (s->tlslog[0]) P("%s_tls %s", tag, s->tlslog);
    s->tlslog[0] = 0;
}

static void probe_https(int cng, int san) {
    char tag[32]; snprintf(tag, sizeof tag, "https_cng%d_san%d", cng, san);
    tls_ident id; if (!make_cert(&id, cng, san, "localhost")) return;
    server s; server_start(&s, AF_INET, 1);
    if (!acquire_server_cred(&s, id.cert, 0)) { s.stop = 1; server_stop(&s); free_cert(&id); return; }
    char t[64];
    /* 127.0.0.1: unknown CA first, then add IGNORE_UNKNOWN_CA, then IGNORE_CERT_CN_INVALID */
    DWORD r1[] = { SECURITY_FLAG_IGNORE_UNKNOWN_CA, SECURITY_FLAG_IGNORE_CERT_CN_INVALID };
    snprintf(t, sizeof t, "%s_ip", tag); fetch(t, "127.0.0.1", s.port, 1, INTERNET_OPEN_TYPE_DIRECT, r1, 2);
    snprintf(t, sizeof t, "%s_ip_srv", tag); dump_server(&s, t);
    /* localhost: CN matches */
    DWORD r2[] = { SECURITY_FLAG_IGNORE_UNKNOWN_CA, SECURITY_FLAG_IGNORE_CERT_CN_INVALID };
    snprintf(t, sizeof t, "%s_lh", tag); fetch(t, "localhost", s.port, 1, INTERNET_OPEN_TYPE_DIRECT, r2, 2);
    snprintf(t, sizeof t, "%s_lh_srv", tag); dump_server(&s, t);
    /* all three ignore flags up front via the request flags in one go is equivalent; also try SCH_CREDENTIALS server */
    P("%s conns=%d stop_ms=%.1f", tag, s.nconn, server_stop(&s));
    FreeCredentialsHandle(&s.cred);
    if (cng && san) {
        server s2; server_start(&s2, AF_INET, 1);
        if (acquire_server_cred(&s2, id.cert, 1)) {
            DWORD r3[] = { SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID };
            fetch("https_schcred_ip", "127.0.0.1", s2.port, 1, INTERNET_OPEN_TYPE_DIRECT, r3, 1);
            dump_server(&s2, "https_schcred_srv");
            FreeCredentialsHandle(&s2.cred);
        }
        P("https_schcred stop_ms=%.1f", server_stop(&s2));
    }
    free_cert(&id);
}

/* ------------------------------------------------------------------ serial throughput */
static int spew(long n, int buffered) {
    static char big[1 << 16];
    if (buffered) setvbuf(stdout, big, _IOFBF, sizeof big); else setvbuf(stdout, NULL, _IONBF, 0);
    double t0 = now_ms(); long w = 0; int line = 0;
    while (w < n) { w += printf("L%06d abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRST\n", line++); }
    fflush(stdout); double dt = now_ms() - t0;
    printf("P spew bytes=%ld lines=%d buffered=%d ms=%.1f kBps=%.1f\n", w, line, buffered, dt, w / dt); fflush(stdout);
    return 0;
}
static int com1_direct(long n) {
    double t0 = now_ms();
    HANDLE h = CreateFileA("\\\\.\\COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { printf("P com1_open err=%lu\n", GetLastError()); return 1; }
    DCB d = { sizeof d }; GetCommState(h, &d); DWORD oldbaud = d.BaudRate; d.BaudRate = CBR_115200; d.ByteSize = 8; d.Parity = NOPARITY; d.StopBits = ONESTOPBIT; BOOL sc = SetCommState(h, &d);
    COMMTIMEOUTS to = {0}; to.WriteTotalTimeoutConstant = 10000; to.WriteTotalTimeoutMultiplier = 1; SetCommTimeouts(h, &to);
    char buf[4096]; for (int i = 0; i < (int)sizeof buf; i++) buf[i] = (i % 64 == 63) ? '\n' : 'a' + i % 26;
    long w = 0; DWORD wr;
    while (w < n) { if (!WriteFile(h, buf, sizeof buf, &wr, NULL) || !wr) break; w += wr; }
    double dt = now_ms() - t0; char m[160];
    int ml = snprintf(m, sizeof m, "\nP com1_direct bytes=%ld ms=%.1f kBps=%.1f oldbaud=%lu setstate=%d\n", w, dt, w / dt, oldbaud, sc);
    WriteFile(h, m, ml, &wr, NULL); FlushFileBuffers(h); CloseHandle(h);
    return 0;
}

/* ================================================================== round 2 (--r2) */
typedef struct { DWORD dwSize; BOOL fSecure; SecPkgContext_ConnectionInfo connectionInfo; SecPkgContext_CipherInfo cipherInfo; } SECCONN_FULL;

/* second listener on [::1] with the same port as an AF_INET server, so "localhost" (resolves ::1 first) connects at once */
static SOCKET add_v6_same_port(unsigned short port) {
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP); struct sockaddr_in6 a = {0};
    a.sin6_family = AF_INET6; a.sin6_addr = in6addr_loopback; a.sin6_port = htons(port);
    BOOL excl = TRUE; setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&excl, sizeof excl);
    if (bind(s, (void *)&a, sizeof a) || listen(s, 16)) { P("v6_same_port bind err=%d", WSAGetLastError()); closesocket(s); return INVALID_SOCKET; }
    return s;
}
typedef struct { SOCKET l; volatile LONG stop; volatile LONG n; } v6fwd;
/* minimal: accept on ::1 and answer like the v4 server (plain HTTP only) */
static DWORD WINAPI v6_accept(LPVOID p) {
    v6fwd *f = p;
    while (!f->stop) { SOCKET c = accept_wait(f->l, 100); if (c == INVALID_SOCKET) continue; InterlockedIncrement(&f->n);
        set_timeouts(c, 3000); char b[4096]; if (read_head(c, b, sizeof b) > 0) send(c, RESP, sizeof RESP - 1, 0); shutdown(c, SD_SEND); closesocket(c); }
    return 0;
}

/* one request with flags applied BEFORE the first send */
static DWORD fetch_pre(const char *tag, HINTERNET hi, const char *host, unsigned short port, DWORD open_flags, DWORD pre_secflags) {
    double t0 = now_ms();
    HINTERNET hc = InternetConnectA(hi, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = HttpOpenRequestA(hc, "GET", "/q", NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_SECURE | open_flags, 0);
    DWORD f0 = 0, l = sizeof f0; InternetQueryOptionA(hr, INTERNET_OPTION_SECURITY_FLAGS, &f0, &l);
    if (pre_secflags) { DWORD f = f0 | pre_secflags; InternetSetOptionA(hr, INTERNET_OPTION_SECURITY_FLAGS, &f, sizeof f); }
    BOOL ok = HttpSendRequestA(hr, NULL, 0, NULL, 0); DWORD err = ok ? 0 : GetLastError();
    DWORD sf = 0; l = sizeof sf; InternetQueryOptionA(hr, INTERNET_OPTION_SECURITY_FLAGS, &sf, &l);
    SECCONN_FULL ci; memset(&ci, 0, sizeof ci); ci.dwSize = sizeof ci; l = sizeof ci;
    BOOL qi = InternetQueryOptionA(hr, INTERNET_OPTION_SECURITY_CONNECTION_INFO, &ci, &l);
    char body[16] = {0}; DWORD rd = 0; if (ok) InternetReadFile(hr, body, sizeof body - 1, &rd);
    P("%s flags_before=0x%lx send=%d err=%lu secflags_after=0x%lx ms=%.1f body=[%s] conninfo=%d/%lu size=%u l=%lu secure=%d proto=0x%lx cipher=0x%x suite=0x%lx",
      tag, f0, ok, err, sf, now_ms() - t0, body, qi, qi ? 0 : GetLastError(), (unsigned)sizeof ci, l, ci.fSecure, ci.connectionInfo.dwProtocol, ci.connectionInfo.aiCipher, ci.cipherInfo.dwCipherSuite);
    InternetCloseHandle(hr); InternetCloseHandle(hc); return err;
}

static void r2_https(void) {
    tls_ident id; if (!make_cert(&id, 1, 1, "localhost")) return;
    /* A: per-host:port certificate decision cache - same port, new sessions, no flags */
    server s; server_start(&s, AF_INET, 1); acquire_server_cred(&s, id.cert, 0);
    HINTERNET h1 = InternetOpenA("i7proto/2", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    fetch_pre("cache_s1_noflags", h1, "127.0.0.1", s.port, 0, 0);
    fetch_pre("cache_s1_ignoreca", h1, "127.0.0.1", s.port, 0, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    fetch_pre("cache_s1_again_noflags", h1, "127.0.0.1", s.port, 0, 0);
    InternetCloseHandle(h1);
    HINTERNET h2 = InternetOpenA("i7proto/2", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    fetch_pre("cache_s2_noflags_samehost", h2, "127.0.0.1", s.port, 0, 0);
    fetch_pre("cache_s2_noflags_localhost", h2, "localhost", s.port, 0, 0);
    InternetCloseHandle(h2);
    dump_server(&s, "cache_srv");
    P("cache conns=%d stop_ms=%.1f", s.nconn, server_stop(&s)); FreeCredentialsHandle(&s.cred);
    /* B: request-flag spelling of the ignore bits, fresh port each */
    server t; server_start(&t, AF_INET, 1); acquire_server_cred(&t, id.cert, 0);
    HINTERNET h3 = InternetOpenA("i7proto/2", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    fetch_pre("openflag_cn_only", h3, "localhost", t.port, INTERNET_FLAG_IGNORE_CERT_CN_INVALID, 0);
    fetch_pre("openflag_cn_plus_setopt_ca", h3, "localhost", t.port, INTERNET_FLAG_IGNORE_CERT_CN_INVALID, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    InternetCloseHandle(h3);
    dump_server(&t, "openflag_srv");
    P("openflag conns=%d stop_ms=%.1f", t.nconn, server_stop(&t)); FreeCredentialsHandle(&t.cred);
    /* C: set the flags on the SESSION handle (documented only per request; observe) */
    server u; server_start(&u, AF_INET, 1); acquire_server_cred(&u, id.cert, 0);
    HINTERNET h4 = InternetOpenA("i7proto/2", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    DWORD f = SECURITY_FLAG_IGNORE_UNKNOWN_CA; BOOL so = InternetSetOptionA(h4, INTERNET_OPTION_SECURITY_FLAGS, &f, sizeof f);
    P("sessionflags set ok=%d err=%lu", so, so ? 0 : GetLastError());
    fetch_pre("sessionflags_req", h4, "localhost", u.port, 0, 0);
    InternetCloseHandle(h4);
    P("sessionflags conns=%d stop_ms=%.1f", u.nconn, server_stop(&u)); FreeCredentialsHandle(&u.cred);
    free_cert(&id);
}

static void r2_refused_and_dualstack(void) {
    /* a port with nothing listening: raw connect time and wininet error/time */
    unsigned short p; SOCKET l = listen_on(AF_INET, &p); closesocket(l);
    SOCKET c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons(p);
    double t0 = now_ms(); int r = connect(c, (void *)&a, sizeof a); P("refused_raw4 rc=%d wsa=%d ms=%.1f", r, r ? WSAGetLastError() : 0, now_ms() - t0); closesocket(c);
    SOCKET c6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP); struct sockaddr_in6 a6 = {0}; a6.sin6_family = AF_INET6; a6.sin6_addr = in6addr_loopback; a6.sin6_port = htons(p);
    t0 = now_ms(); r = connect(c6, (void *)&a6, sizeof a6); P("refused_raw6 rc=%d wsa=%d ms=%.1f", r, r ? WSAGetLastError() : 0, now_ms() - t0); closesocket(c6);
    char url[128]; snprintf(url, sizeof url, "http://127.0.0.1:%u/x", p);
    open_url_bounded("refused_wininet_ip", INTERNET_OPEN_TYPE_DIRECT, url, 30000);
    snprintf(url, sizeof url, "http://localhost:%u/x", p);
    open_url_bounded("refused_wininet_localhost", INTERNET_OPEN_TYPE_DIRECT, url, 30000);
    /* v4-only server again, fresh process-level name cache? (new port, localhost) then a dual-stack one */
    server s; server_start(&s, AF_INET, 0);
    snprintf(url, sizeof url, "http://localhost:%u/v4only", s.port); open_url_timed("localhost_v4only", INTERNET_OPEN_TYPE_DIRECT, url);
    P("v4only stop_ms=%.1f", server_stop(&s));
    server d; server_start(&d, AF_INET, 0);
    v6fwd f = {0}; f.l = add_v6_same_port(d.port); HANDLE th = f.l != INVALID_SOCKET ? CreateThread(NULL, 0, v6_accept, &f, 0, NULL) : NULL;
    snprintf(url, sizeof url, "http://localhost:%u/dual", d.port); open_url_timed("localhost_dualstack", INTERNET_OPEN_TYPE_DIRECT, url);
    snprintf(url, sizeof url, "http://[::1]:%u/v6lit", d.port); open_url_timed("v6_literal", INTERNET_OPEN_TYPE_DIRECT, url);
    P("dualstack v4conns=%d v6conns=%ld", d.nconn, f.n);
    f.stop = 1; if (th) { WaitForSingleObject(th, 3000); CloseHandle(th); } closesocket(f.l);
    P("dualstack stop_ms=%.1f", server_stop(&d));
}

/* tiny FTP server: one control connection, PASV data, records the command sequence */
typedef struct { SOCKET l; unsigned short port; char cmds[2048]; int done; } ftpsrv;
static void ftp_reply(SOCKET c, const char *s) { send(c, s, (int)strlen(s), 0); }
static DWORD WINAPI ftp_thread(LPVOID p) {
    ftpsrv *f = p; SOCKET c = accept_wait(f->l, 8000); if (c == INVALID_SOCKET) return 0;
    set_timeouts(c, 5000); ftp_reply(c, "220 i7 proto ftp\r\n");
    SOCKET dl = INVALID_SOCKET; char line[512]; int n = 0;
    for (int guard = 0; guard < 64; guard++) {
        /* read one line */
        n = 0; char ch; while (n < (int)sizeof line - 1 && recv(c, &ch, 1, 0) == 1) { if (ch == '\n') break; if (ch != '\r') line[n++] = ch; }
        line[n] = 0; if (!n) break;
        if (strlen(f->cmds) + n + 2 < sizeof f->cmds) { strcat(f->cmds, !strncmp(line, "PASS", 4) ? "PASS ***" : line); strcat(f->cmds, "|"); }
        if (!strncmp(line, "USER", 4)) ftp_reply(c, "331 need password\r\n");
        else if (!strncmp(line, "PASS", 4)) ftp_reply(c, "230 logged in\r\n");
        else if (!strncmp(line, "PWD", 3)) ftp_reply(c, "257 \"/\" is cwd\r\n");
        else if (!strncmp(line, "TYPE", 4)) ftp_reply(c, "200 type ok\r\n");
        else if (!strncmp(line, "CWD", 3)) ftp_reply(c, "250 ok\r\n");
        else if (!strncmp(line, "PASV", 4)) {
            unsigned short dp; dl = listen_on(AF_INET, &dp); char r[96];
            snprintf(r, sizeof r, "227 Entering Passive Mode (127,0,0,1,%u,%u)\r\n", dp >> 8, dp & 255); ftp_reply(c, r);
        } else if (!strncmp(line, "LIST", 4) || !strncmp(line, "NLST", 4)) {
            ftp_reply(c, "150 here it comes\r\n");
            SOCKET d = dl != INVALID_SOCKET ? accept_wait(dl, 5000) : INVALID_SOCKET;
            if (d != INVALID_SOCKET) { const char *ls = "-rw-r--r--   1 owner    group          5 Jan 01  2020 hello.txt\r\n"; send(d, ls, (int)strlen(ls), 0); shutdown(d, SD_SEND); closesocket(d); }
            if (dl != INVALID_SOCKET) { closesocket(dl); dl = INVALID_SOCKET; }
            ftp_reply(c, d != INVALID_SOCKET ? "226 done\r\n" : "425 no data\r\n");
        } else if (!strncmp(line, "QUIT", 4)) { ftp_reply(c, "221 bye\r\n"); break; }
        else ftp_reply(c, "502 not implemented\r\n");
    }
    if (dl != INVALID_SOCKET) closesocket(dl);
    closesocket(c); f->done = 1; return 0;
}
static void r2_ftp(void) {
    ftpsrv f; memset(&f, 0, sizeof f); f.l = listen_on(AF_INET, &f.port);
    HANDLE th = CreateThread(NULL, 0, ftp_thread, &f, 0, NULL);
    double t0 = now_ms();
    HINTERNET hi = InternetOpenA("i7proto/2", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    DWORD to = 5000; InternetSetOptionA(hi, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to); InternetSetOptionA(hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
    HINTERNET hc = InternetConnectA(hi, "127.0.0.1", f.port, "anonymous", "x@y", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    P("ftp connect=%d err=%lu ms=%.1f", hc != NULL, hc ? 0 : GetLastError(), now_ms() - t0);
    if (hc) {
        char cwd[MAX_PATH] = ""; DWORD cl = sizeof cwd; BOOL ok = FtpGetCurrentDirectoryA(hc, cwd, &cl);
        P("ftp pwd ok=%d err=%lu cwd=[%s]", ok, ok ? 0 : GetLastError(), cwd);
        WIN32_FIND_DATAA fd; HINTERNET hf = FtpFindFirstFileA(hc, NULL, &fd, INTERNET_FLAG_RELOAD, 0);
        P("ftp find=%d err=%lu name=[%s] size=%lu", hf != NULL, hf ? 0 : GetLastError(), hf ? fd.cFileName : "", hf ? fd.nFileSizeLow : 0);
        if (hf) InternetCloseHandle(hf);
        InternetCloseHandle(hc);
    }
    InternetCloseHandle(hi);
    closesocket(f.l); /* unblocks a pending accept */
    if (WaitForSingleObject(th, 8000)) P("ftp thread HANG"); CloseHandle(th);
    P("ftp cmds %s total_ms=%.1f", f.cmds, now_ms() - t0);
}

static int round2(void) {
    WSADATA wd; WSAStartup(MAKEWORD(2, 2), &wd);
    SYSTEMTIME u, lt; GetSystemTime(&u); GetLocalTime(&lt); TIME_ZONE_INFORMATION tz; DWORD tzr = GetTimeZoneInformation(&tz);
    P("clock utc=%04u-%02u-%02uT%02u:%02u:%02u local=%02u:%02u tzbias=%ld tzid=%lu", u.wYear, u.wMonth, u.wDay, u.wHour, u.wMinute, u.wSecond, lt.wHour, lt.wMinute, tz.Bias, tzr);
    double T0 = now_ms();
    r2_refused_and_dualstack();
    r2_https();
    r2_ftp();
    P("r2_total_ms %.1f", now_ms() - T0);
    WSACleanup(); return 0;
}

int main(int argc, char **argv) {
    QueryPerformanceFrequency(&g_qf);
    if (argc > 1 && !strcmp(argv[1], "--r2")) { setvbuf(stdout, NULL, _IONBF, 0); SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX); return round2(); }
    setvbuf(stdout, NULL, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc > 2 && !strcmp(argv[1], "--spew")) return spew(atol(argv[2]), argc > 3);
    if (argc > 2 && !strcmp(argv[1], "--com1")) return com1_direct(atol(argv[2]));
    if (argc > 1 && !strcmp(argv[1], "--hang")) { printf("P hang start\n"); Sleep(INFINITE); }
    if (argc > 1 && !strcmp(argv[1], "--crash")) { printf("P crash start\n"); *(volatile int *)0 = 1; }

    WSADATA wd; WSAStartup(MAKEWORD(2, 2), &wd);
    OSVERSIONINFOW v = { sizeof v }; LONG (WINAPI *rgv)(OSVERSIONINFOW *) = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (rgv) rgv(&v);
    P("os %lu.%lu.%lu uptime_ms=%llu", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber, GetTickCount64());
    { char p[MAX_PATH]; GetModuleFileNameA(GetModuleHandleA("wininet.dll"), p, sizeof p); DWORD z, sz = GetFileVersionInfoSizeA(p, &z);
      void *vb = malloc(sz ? sz : 1); VS_FIXEDFILEINFO *ff; UINT fl;
      if (sz && GetFileVersionInfoA(p, 0, sz, vb) && VerQueryValueA(vb, "\\", (void **)&ff, &fl))
          P("wininet_version %u.%u.%u.%u", HIWORD(ff->dwFileVersionMS), LOWORD(ff->dwFileVersionMS), HIWORD(ff->dwFileVersionLS), LOWORD(ff->dwFileVersionLS));
      free(vb); }

    double T0 = now_ms();
    probe_loopback(AF_INET, "loop4");
    probe_loopback(AF_INET6, "loop6");
    probe_resolve("localhost"); probe_resolve("127.0.0.1"); probe_resolve("i7-nonexistent-host.invalid");
    probe_proxy_config();

    /* plain HTTP via wininet, DIRECT first (no autodetect), then PRECONFIG (autodetect path) */
    server s; if (!server_start(&s, AF_INET, 0)) { P("http_server FAIL"); return 1; }
    char url[128];
    snprintf(url, sizeof url, "http://127.0.0.1:%u/direct", s.port);
    open_url_timed("http_direct_1", INTERNET_OPEN_TYPE_DIRECT, url);
    dump_server(&s, "http_direct_1_wire");
    open_url_timed("http_direct_2", INTERNET_OPEN_TYPE_DIRECT, url);
    dump_server(&s, "http_direct_2_wire");
    snprintf(url, sizeof url, "http://localhost:%u/lh", s.port);
    open_url_timed("http_direct_localhost", INTERNET_OPEN_TYPE_DIRECT, url);
    dump_server(&s, "http_direct_localhost_wire");
    snprintf(url, sizeof url, "http://127.0.0.1:%u/pre", s.port);
    open_url_bounded("http_preconfig_1", INTERNET_OPEN_TYPE_PRECONFIG, url, 60000);
    open_url_bounded("http_preconfig_2", INTERNET_OPEN_TYPE_PRECONFIG, url, 60000);
    snprintf(url, sizeof url, "http://localhost:%u/prelh", s.port);
    open_url_bounded("http_preconfig_localhost", INTERNET_OPEN_TYPE_PRECONFIG, url, 60000);
    dump_server(&s, "http_preconfig_wire");
    /* name that does not resolve: DIRECT and PRECONFIG */
    open_url_bounded("http_direct_nxdomain", INTERNET_OPEN_TYPE_DIRECT, "http://i7-nonexistent-host.invalid/", 30000);
    open_url_bounded("http_preconfig_nxdomain", INTERNET_OPEN_TYPE_PRECONFIG, "http://i7-nonexistent-host.invalid/", 60000);
    P("http_server conns=%d stop_ms=%.1f", s.nconn, server_stop(&s));
    { HANDLE h = CreateThread(NULL, 0, bg_detect, NULL, 0, NULL); if (WaitForSingleObject(h, 60000)) P("wpad_detect STILL_RUNNING"); CloseHandle(h); }

    /* HTTPS: CAPI key without SAN, CNG key with SAN+EKU */
    probe_https(0, 0);
    probe_https(1, 1);
    P("total_ms %.1f", now_ms() - T0);
    WSACleanup();
    return 0;
}
