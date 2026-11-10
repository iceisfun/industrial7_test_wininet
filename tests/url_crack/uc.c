/* url_crack area: helper implementations (see uc.h). */
#include "uc.h"

static int is_ascii(const char *s) { if (!s) return 1; for (; *s; s++) if ((unsigned char)*s > 0x7e) return 0; return 1; }

const WCHAR *uc_w(const char *s) {
    static WCHAR b[8][8192]; static int k;
    WCHAR *o = b[k++ & 7];
    if (!s) return NULL;
    if (!MultiByteToWideChar(CP_UTF8, 0, s, -1, o, 8192)) o[0] = 0;
    return o;
}
const char *uc_a(const WCHAR *w) {
    static char b[8][16384]; static int k;
    char *o = b[k++ & 7];
    if (!w) return NULL;
    if (!WideCharToMultiByte(CP_UTF8, 0, w, -1, o, sizeof b[0], NULL, NULL)) o[0] = 0;
    return o;
}

void uc_crackA(const char *url, DWORD flags, int want_extra, uc_crack_t *o) {
    URL_COMPONENTSA c;
    memset(o, 0, sizeof *o);
    memset(&c, 0, sizeof c);
    c.dwStructSize = sizeof c;
    c.lpszScheme = o->scheme;   c.dwSchemeLength = sizeof o->scheme;
    c.lpszHostName = o->host;   c.dwHostNameLength = sizeof o->host;
    c.lpszUserName = o->user;   c.dwUserNameLength = sizeof o->user;
    c.lpszPassword = o->pass;   c.dwPasswordLength = sizeof o->pass;
    c.lpszUrlPath = o->path;    c.dwUrlPathLength = sizeof o->path;
    if (want_extra) { c.lpszExtraInfo = o->extra; c.dwExtraInfoLength = sizeof o->extra; }
    c.nScheme = (INTERNET_SCHEME)0x77; c.nPort = 0x7777;
    static char ubuf[UC_BUF * 4];
    lstrcpynA(ubuf, url, sizeof ubuf);
    SetLastError(0xdeadbeef);
    o->r = U(InternetCrackUrlA)(ubuf, 0, flags, &c);
    o->err = GetLastError();
    o->ns = c.nScheme; o->port = c.nPort;
    o->lscheme = c.dwSchemeLength; o->lhost = c.dwHostNameLength; o->luser = c.dwUserNameLength;
    o->lpass = c.dwPasswordLength; o->lpath = c.dwUrlPathLength; o->lextra = c.dwExtraInfoLength;
}

void uc_crackW(const char *url, DWORD flags, int want_extra, uc_crack_t *o) {
    static WCHAR s[UC_BUF], h[UC_BUF], u[UC_BUF], p[UC_BUF], pa[UC_BUF * 4], x[UC_BUF * 4];
    URL_COMPONENTSW c;
    memset(o, 0, sizeof *o);
    memset(&c, 0, sizeof c);
    s[0] = h[0] = u[0] = p[0] = pa[0] = x[0] = 0;
    c.dwStructSize = sizeof c;
    c.lpszScheme = s;   c.dwSchemeLength = UC_BUF;
    c.lpszHostName = h; c.dwHostNameLength = UC_BUF;
    c.lpszUserName = u; c.dwUserNameLength = UC_BUF;
    c.lpszPassword = p; c.dwPasswordLength = UC_BUF;
    c.lpszUrlPath = pa; c.dwUrlPathLength = UC_BUF * 4;
    if (want_extra) { c.lpszExtraInfo = x; c.dwExtraInfoLength = UC_BUF * 4; }
    c.nScheme = (INTERNET_SCHEME)0x77; c.nPort = 0x7777;
    SetLastError(0xdeadbeef);
    o->r = U(InternetCrackUrlW)(uc_w(url), 0, flags, &c);
    o->err = GetLastError();
    o->ns = c.nScheme; o->port = c.nPort;
    strcpy(o->scheme, uc_a(s)); strcpy(o->host, uc_a(h)); strcpy(o->user, uc_a(u));
    strcpy(o->pass, uc_a(p)); strcpy(o->path, uc_a(pa)); strcpy(o->extra, uc_a(x));
    o->lscheme = c.dwSchemeLength; o->lhost = c.dwHostNameLength; o->luser = c.dwUserNameLength;
    o->lpass = c.dwPasswordLength; o->lpath = c.dwUrlPathLength; o->lextra = c.dwExtraInfoLength;
}

#define VCHK(cond, ...) t_check(!!(cond), file, line, #cond, __VA_ARGS__)
static void cmp_str(const char *what, const char *api, const char *url, const char *got, DWORD glen, const char *want, int wide,
                    const char *file, int line) {
    if (!want) return;
    VCHK(!strcmp(got, want), "%s %s(\"%s\"): got \"%s\" want \"%s\"", api, what, url, got, want);
    /* lengths are characters without the NUL, both for A (bytes) and W (WCHARs) */
    DWORD wl = wide ? (DWORD)MultiByteToWideChar(CP_UTF8, 0, want, -1, NULL, 0) - 1 : (DWORD)strlen(want);
    VCHK(glen == wl, "%s %s(\"%s\") length: got %lu want %lu", api, what, url, glen, wl);
}

static void check_one(const uc_crack_vec *v, const uc_crack_t *o, int want_extra, const char *api, int wide, const char *file, int line) {
    const char *u = v->url;
    if (!v->r) {
        VCHK(!o->r, "%s(\"%s\") succeeded, want error %lu", api, u, v->err);
        VCHK(o->err == v->err, "%s(\"%s\") error: got %lu want %lu", api, u, o->err, v->err);
        return;
    }
    VCHK(o->r, "%s(\"%s\") failed with %lu", api, u, o->err);
    if (!o->r) return;
    VCHK(o->err == 0, "%s(\"%s\") last error after success: got %lu want 0", api, u, o->err);
    if (v->ns != UC_NS_ANY) VCHK(o->ns == v->ns, "%s(\"%s\") nScheme: got %d want %d", api, u, o->ns, v->ns);
    if (v->port >= 0) VCHK(o->port == (unsigned)v->port, "%s(\"%s\") nPort: got %u want %d", api, u, o->port, v->port);
    cmp_str("scheme", api, u, o->scheme, o->lscheme, v->scheme, wide, file, line);
    cmp_str("host", api, u, o->host, o->lhost, v->host, wide, file, line);
    cmp_str("user", api, u, o->user, o->luser, v->user, wide, file, line);
    cmp_str("password", api, u, o->pass, o->lpass, v->pass, wide, file, line);
    if (want_extra) {
        cmp_str("path", api, u, o->path, o->lpath, v->path, wide, file, line);
        cmp_str("extra", api, u, o->extra, o->lextra, v->extra, wide, file, line);
    } else if (v->path) {
        char full[UC_BUF * 8];
        if (v->fullpath) strcpy(full, v->fullpath);
        else snprintf(full, sizeof full, "%s%s", v->path, v->extra ? v->extra : "");
        cmp_str("path(no extra buffer)", api, u, o->path, o->lpath, full, wide, file, line);
    }
}

void uc_check_crack_vec(const uc_crack_vec *v, const char *file, int line) {
    static uc_crack_t o;
    if (v->only != 2) {
        uc_crackA(v->url, 0, 1, &o); check_one(v, &o, 1, "InternetCrackUrlA", 0, file, line);
        uc_crackA(v->url, 0, 0, &o); check_one(v, &o, 0, "InternetCrackUrlA[noextra]", 0, file, line);
    }
    if (v->only != 1) {
        uc_crackW(v->url, 0, 1, &o); check_one(v, &o, 1, "InternetCrackUrlW", 1, file, line);
        uc_crackW(v->url, 0, 0, &o); check_one(v, &o, 0, "InternetCrackUrlW[noextra]", 1, file, line);
    }
}

static void fvec_check(const uc_crack_fvec *v, DWORD flags, int wide, const char *file, int line) {
    static uc_crack_t o;
    const char *u = v->url;
    const char *api = wide ? "InternetCrackUrlW[flags]" : "InternetCrackUrlA[flags]";
    if (wide) uc_crackW(u, flags, 1, &o); else uc_crackA(u, flags, 1, &o);
    if (!v->r) {
        VCHK(!o.r && o.err == v->err, "%s(\"%s\", 0x%08lx): r=%d err=%lu, want error %lu", api, u, flags, o.r, o.err, v->err);
        return;
    }
    VCHK(o.r, "%s(\"%s\", 0x%08lx) failed %lu", api, u, flags, o.err);
    if (!o.r) return;
    if (v->ns != UC_NS_ANY) VCHK(o.ns == v->ns, "%s(\"%s\", 0x%08lx) nScheme %d want %d", api, u, flags, o.ns, v->ns);
    if (v->port >= 0) VCHK(o.port == (unsigned)v->port, "%s(\"%s\", 0x%08lx) nPort %u want %d", api, u, flags, o.port, v->port);
    cmp_str("scheme", api, u, o.scheme, o.lscheme, v->scheme, wide, file, line);
    cmp_str("host", api, u, o.host, o.lhost, v->host, wide, file, line);
    cmp_str("user", api, u, o.user, o.luser, v->user, wide, file, line);
    cmp_str("password", api, u, o.pass, o.lpass, v->pass, wide, file, line);
    VCHK(!strcmp(o.path, v->path), "%s(\"%s\", 0x%08lx) path \"%s\" want \"%s\"", api, u, flags, o.path, v->path);
    VCHK(o.lpath == v->lpath, "%s(\"%s\", 0x%08lx) path length %lu want %lu", api, u, flags, o.lpath, v->lpath);
    VCHK(!strcmp(o.extra, v->extra), "%s(\"%s\", 0x%08lx) extra \"%s\" want \"%s\"", api, u, flags, o.extra, v->extra);
    VCHK(o.lextra == v->lextra, "%s(\"%s\", 0x%08lx) extra length %lu want %lu", api, u, flags, o.lextra, v->lextra);
}

void uc_check_crack_fvec(const uc_crack_fvec *v, DWORD flags, const char *file, int line) { fvec_check(v, flags, 0, file, line); }
void uc_check_crack_fvecW(const uc_crack_fvec *v, DWORD flags, const char *file, int line) { fvec_check(v, flags, 1, file, line); }

void uc_check_canon(const char *url, DWORD flags, const char *want, DWORD err, const char *file, int line) {
    uc_check_canon_m(url, flags, want, err, 3, file, line);
}
void uc_check_canon_m(const char *url, DWORD flags, const char *want, DWORD err, int which, const char *file, int line) {
    char out[4096]; DWORD n = sizeof out; BOOL r; DWORD e;
    strcpy(out, "~");
    if (which & 1) {
    SetLastError(0xdeadbeef);
    r = U(InternetCanonicalizeUrlA)(url, out, &n, flags);
    e = GetLastError();
    if (want) {
        VCHK(r, "InternetCanonicalizeUrlA(\"%s\", 0x%08lx) failed %lu", url, flags, e);
        if (r) {
            VCHK(!strcmp(out, want), "InternetCanonicalizeUrlA(\"%s\", 0x%08lx): got \"%s\" want \"%s\"", url, flags, out, want);
            VCHK(n == strlen(out), "InternetCanonicalizeUrlA(\"%s\", 0x%08lx) length: got %lu want %u", url, flags, n, (unsigned)strlen(out));
            VCHK(e == 0, "InternetCanonicalizeUrlA(\"%s\", 0x%08lx) last error after success: %lu", url, flags, e);
        }
    } else {
        VCHK(!r, "InternetCanonicalizeUrlA(\"%s\", 0x%08lx) succeeded (\"%s\"), want error %lu", url, flags, out, err);
        VCHK(e == err, "InternetCanonicalizeUrlA(\"%s\", 0x%08lx) error: got %lu want %lu", url, flags, e, err);
    }
    }
    if (!(which & 2)) return;
    if (which == 3 && (!is_ascii(url) || !is_ascii(want))) return;
    WCHAR wout[4096]; DWORD wn = 4096;
    wout[0] = 0;
    SetLastError(0xdeadbeef);
    r = U(InternetCanonicalizeUrlW)(uc_w(url), wout, &wn, flags);
    e = GetLastError();
    if (want) {
        VCHK(r, "InternetCanonicalizeUrlW(\"%s\", 0x%08lx) failed %lu", url, flags, e);
        if (r) {
            const char *a = uc_a(wout);
            VCHK(!strcmp(a, want), "InternetCanonicalizeUrlW(\"%s\", 0x%08lx): got \"%s\" want \"%s\"", url, flags, a, want);
            VCHK(wn == (DWORD)lstrlenW(wout), "InternetCanonicalizeUrlW(\"%s\", 0x%08lx) length: got %lu want %d", url, flags, wn, lstrlenW(wout));
        }
    } else {
        VCHK(!r, "InternetCanonicalizeUrlW(\"%s\", 0x%08lx) succeeded, want error %lu", url, flags, err);
        VCHK(e == err, "InternetCanonicalizeUrlW(\"%s\", 0x%08lx) error: got %lu want %lu", url, flags, e, err);
    }
}

void uc_check_combine(const char *base, const char *rel, DWORD flags, const char *want, DWORD err, const char *file, int line) {
    uc_check_combine_m(base, rel, flags, want, err, 3, file, line);
}
void uc_check_combine_m(const char *base, const char *rel, DWORD flags, const char *want, DWORD err, int which, const char *file, int line) {
    char out[4096]; DWORD n = sizeof out; BOOL r; DWORD e;
    strcpy(out, "~");
    if (which & 1) {
    SetLastError(0xdeadbeef);
    r = U(InternetCombineUrlA)(base, rel, out, &n, flags);
    e = GetLastError();
    if (want) {
        VCHK(r, "InternetCombineUrlA(\"%s\", \"%s\", 0x%08lx) failed %lu", base, rel, flags, e);
        if (r) {
            VCHK(!strcmp(out, want), "InternetCombineUrlA(\"%s\", \"%s\", 0x%08lx): got \"%s\" want \"%s\"", base, rel, flags, out, want);
            VCHK(n == strlen(out), "InternetCombineUrlA(\"%s\", \"%s\", 0x%08lx) length: got %lu want %u", base, rel, flags, n, (unsigned)strlen(out));
            VCHK(e == 0, "InternetCombineUrlA(\"%s\", \"%s\") last error after success: %lu", base, rel, e);
        }
    } else {
        VCHK(!r, "InternetCombineUrlA(\"%s\", \"%s\", 0x%08lx) succeeded (\"%s\"), want error %lu", base, rel, flags, out, err);
        VCHK(e == err, "InternetCombineUrlA(\"%s\", \"%s\", 0x%08lx) error: got %lu want %lu", base, rel, flags, e, err);
    }
    }
    if (!(which & 2)) return;
    if (which == 3 && (!is_ascii(base) || !is_ascii(rel) || !is_ascii(want))) return;
    WCHAR wout[4096]; DWORD wn = 4096;
    wout[0] = 0;
    SetLastError(0xdeadbeef);
    r = U(InternetCombineUrlW)(uc_w(base), uc_w(rel), wout, &wn, flags);
    e = GetLastError();
    if (want) {
        VCHK(r, "InternetCombineUrlW(\"%s\", \"%s\", 0x%08lx) failed %lu", base, rel, flags, e);
        if (r) {
            const char *a = uc_a(wout);
            VCHK(!strcmp(a, want), "InternetCombineUrlW(\"%s\", \"%s\", 0x%08lx): got \"%s\" want \"%s\"", base, rel, flags, a, want);
            VCHK(wn == (DWORD)lstrlenW(wout), "InternetCombineUrlW(\"%s\", \"%s\") length: got %lu want %d", base, rel, wn, lstrlenW(wout));
        }
    } else {
        VCHK(!r, "InternetCombineUrlW(\"%s\", \"%s\", 0x%08lx) succeeded, want error %lu", base, rel, flags, err);
        VCHK(e == err, "InternetCombineUrlW(\"%s\", \"%s\", 0x%08lx) error: got %lu want %lu", base, rel, flags, e, err);
    }
}

void uc_check_create(const uc_create_in *in, DWORD flags, const char *want, DWORD err, int qextra, const char *file, int line) {
    URL_COMPONENTSA c; char out[4096]; DWORD n; BOOL r; DWORD e;
    const char *tag = want ? want : "(fail)";
    memset(&c, 0, sizeof c);
    c.dwStructSize = sizeof c; c.nScheme = in->ns; c.nPort = (INTERNET_PORT)in->port;
    c.lpszScheme = (LPSTR)in->scheme; c.lpszHostName = (LPSTR)in->host; c.lpszUserName = (LPSTR)in->user;
    c.lpszPassword = (LPSTR)in->pass; c.lpszUrlPath = (LPSTR)in->path; c.lpszExtraInfo = (LPSTR)in->extra;
    /* size query first: NULL buffer -> 122 + required size in bytes including the NUL */
    n = 0x55; SetLastError(0xdeadbeef);
    r = U(InternetCreateUrlA)(&c, flags, NULL, &n);
    e = GetLastError();
    if (want) {
        VCHK(!r && e == ERROR_INSUFFICIENT_BUFFER, "InternetCreateUrlA size query for \"%s\": r=%d err=%lu", tag, r, e);
        VCHK(n == strlen(want) + 1 + qextra, "InternetCreateUrlA size query for \"%s\": got %lu want %u", tag, n, (unsigned)(strlen(want) + 1 + qextra));
    } else {
        VCHK(!r && e == err, "InternetCreateUrlA size query (want error %lu): r=%d err=%lu", err, r, e);
    }
    n = sizeof out; strcpy(out, "~"); SetLastError(0xdeadbeef);
    r = U(InternetCreateUrlA)(&c, flags, out, &n);
    e = GetLastError();
    if (want) {
        VCHK(r, "InternetCreateUrlA(\"%s\", 0x%08lx) failed %lu", tag, flags, e);
        if (r) {
            VCHK(!strcmp(out, want), "InternetCreateUrlA(0x%08lx): got \"%s\" want \"%s\"", flags, out, want);
            VCHK(n == strlen(want), "InternetCreateUrlA(\"%s\") length: got %lu want %u", tag, n, (unsigned)strlen(want));
        }
    } else {
        VCHK(!r, "InternetCreateUrlA(0x%08lx) succeeded (\"%s\"), want error %lu", flags, out, err);
        VCHK(e == err, "InternetCreateUrlA(0x%08lx) error: got %lu want %lu", flags, e, err);
    }
    if (!is_ascii(in->scheme) || !is_ascii(in->host) || !is_ascii(in->user) || !is_ascii(in->pass) || !is_ascii(in->path) || !is_ascii(in->extra))
        return;
    URL_COMPONENTSW w; WCHAR wout[4096];
    memset(&w, 0, sizeof w);
    w.dwStructSize = sizeof w; w.nScheme = in->ns; w.nPort = (INTERNET_PORT)in->port;
    w.lpszScheme = (LPWSTR)uc_w(in->scheme); w.lpszHostName = (LPWSTR)uc_w(in->host); w.lpszUserName = (LPWSTR)uc_w(in->user);
    w.lpszPassword = (LPWSTR)uc_w(in->pass); w.lpszUrlPath = (LPWSTR)uc_w(in->path); w.lpszExtraInfo = (LPWSTR)uc_w(in->extra);
    n = 0; SetLastError(0xdeadbeef);
    r = U(InternetCreateUrlW)(&w, flags, NULL, &n);
    e = GetLastError();
    if (want) {
        VCHK(!r && e == ERROR_INSUFFICIENT_BUFFER, "InternetCreateUrlW size query for \"%s\": r=%d err=%lu", tag, r, e);
        /* W size query reports BYTES including the NUL */
        VCHK(n == (strlen(want) + 1 + qextra) * 2, "InternetCreateUrlW size query for \"%s\": got %lu want %u", tag, n, (unsigned)(strlen(want) + 1 + qextra) * 2);
    } else {
        VCHK(!r && e == err, "InternetCreateUrlW size query (want error %lu): r=%d err=%lu", err, r, e);
    }
    n = 4096; wout[0] = 0; SetLastError(0xdeadbeef);
    r = U(InternetCreateUrlW)(&w, flags, wout, &n);
    e = GetLastError();
    if (want) {
        VCHK(r, "InternetCreateUrlW(\"%s\") failed %lu", tag, e);
        if (r) {
            const char *a = uc_a(wout);
            VCHK(!strcmp(a, want), "InternetCreateUrlW(0x%08lx): got \"%s\" want \"%s\"", flags, a, want);
            VCHK(n == strlen(want), "InternetCreateUrlW(\"%s\") length (chars): got %lu want %u", tag, n, (unsigned)strlen(want));
        }
    } else {
        VCHK(!r, "InternetCreateUrlW(0x%08lx) succeeded, want error %lu", flags, err);
        VCHK(e == err, "InternetCreateUrlW(0x%08lx) error: got %lu want %lu", flags, e, err);
    }
}
