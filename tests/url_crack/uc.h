/* url_crack area: shared helpers for InternetCrackUrl / CreateUrl / CanonicalizeUrl / CombineUrl tests.
 * All calls go through U()/UIN(); wininet.dll is never linked. */
#ifndef UC_H
#define UC_H
#include "t.h"
#include <wininet.h>

/* Result of one InternetCrackUrl call with every component buffer supplied (size UC_BUF). */
#define UC_BUF 1024
typedef struct {
    BOOL r; DWORD err; int ns; unsigned port;
    char scheme[UC_BUF], host[UC_BUF], user[UC_BUF], pass[UC_BUF], path[UC_BUF * 4], extra[UC_BUF * 4];
    DWORD lscheme, lhost, luser, lpass, lpath, lextra;
} uc_crack_t;

/* want_extra: supply the extra-info buffer (then the path is split at the first ? or #).
 * The URL is copied to a writable buffer first: with dwFlags == 0, InternetCrackUrlA decodes %XX in the
 * authority (user/password/host) IN PLACE in the caller's string (see crack_inplace.c). */
void uc_crackA(const char *url, DWORD flags, int want_extra, uc_crack_t *o);
/* Same through InternetCrackUrlW: url is UTF-8, converted to UTF-16; results converted back to UTF-8,
 * lengths are the raw W lengths (characters). */
void uc_crackW(const char *url, DWORD flags, int want_extra, uc_crack_t *o);

/* One table row for the crack tables. NULL string = "do not check". r=0 rows check err only. */
typedef struct {
    const char *url;
    int r; DWORD err;
    int ns; int port;                     /* ns UC_NS_ANY / port -1 = do not check */
    const char *scheme, *host, *user, *pass, *path, *extra;
    const char *fullpath;                 /* path when no extra buffer is supplied (NULL = path+extra) */
} uc_crack_vec;
#define UC_NS_ANY 0x7fff
void uc_check_crack_vec(const uc_crack_vec *v, const char *file, int line);

/* Flag vectors (ICU_DECODE / ICU_ESCAPE), A only, all buffers incl. extra; explicit path/extra lengths. */
typedef struct {
    const char *url; int r; DWORD err; int ns; int port;
    const char *scheme, *host, *user, *pass, *path; DWORD lpath; const char *extra; DWORD lextra;
} uc_crack_fvec;
void uc_check_crack_fvec(const uc_crack_fvec *v, DWORD flags, const char *file, int line);
#define UC_CRACK_VEC(name, ...) \
    static const uc_crack_vec ucv_##name = { __VA_ARGS__ }; \
    TEST(url_crack_v_##name) { REQUIRE(U(InternetCrackUrlA)); REQUIRE(U(InternetCrackUrlW)); uc_check_crack_vec(&ucv_##name, __FILE__, __LINE__); }

/* Canonicalize: A and W in one go. want == NULL means "must fail with err". */
void uc_check_canon(const char *url, DWORD flags, const char *want, DWORD err, const char *file, int line);
#define CANON(url, flags, want) uc_check_canon((url), (flags), (want), 0, __FILE__, __LINE__)
#define CANON_FAIL(url, flags, err) uc_check_canon((url), (flags), NULL, (err), __FILE__, __LINE__)

/* Combine: A and W. */
void uc_check_combine(const char *base, const char *rel, DWORD flags, const char *want, DWORD err, const char *file, int line);
#define COMBINE(b, r, flags, want) uc_check_combine((b), (r), (flags), (want), 0, __FILE__, __LINE__)
#define COMBINE_FAIL(b, r, flags, err) uc_check_combine((b), (r), (flags), NULL, (err), __FILE__, __LINE__)

/* Create: components given as UTF-8 strings (NULL = not supplied); runs A (buffer + size query) and W. */
typedef struct {
    INTERNET_SCHEME ns; const char *scheme; const char *host; int port;
    const char *user, *pass, *path, *extra;
} uc_create_in;
/* qextra: how many bytes the NULL-buffer size query over-reports beyond strlen(want)+1 (opaque schemes whose path
 * has no leading '/': the separator '/' is counted but not written). */
void uc_check_create(const uc_create_in *in, DWORD flags, const char *want, DWORD err, int qextra, const char *file, int line);
#define CREATE(want, flags, ...) do { uc_create_in in_ = { __VA_ARGS__ }; uc_check_create(&in_, (flags), (want), 0, 0, __FILE__, __LINE__); } while (0)
#define CREATE_Q(want, qextra, flags, ...) do { uc_create_in in_ = { __VA_ARGS__ }; uc_check_create(&in_, (flags), (want), 0, (qextra), __FILE__, __LINE__); } while (0)
#define CREATE_FAIL(err, flags, ...) do { uc_create_in in_ = { __VA_ARGS__ }; uc_check_create(&in_, (flags), NULL, (err), 0, __FILE__, __LINE__); } while (0)

/* UTF-8 <-> UTF-16 scratch conversions (static rotating buffers, 8 slots). */
const WCHAR *uc_w(const char *utf8);
const char *uc_a(const WCHAR *w);
#endif
