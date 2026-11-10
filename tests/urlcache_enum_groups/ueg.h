/* urlcache_enum_groups - shared helpers (area prefix ueg_).
 * Cache enumeration (FindFirst/NextUrlCacheEntry[Ex]A/W, FindCloseUrlCache), cache groups, containers,
 * config info, IsUrlCacheEntryExpired, binary blobs.
 * Isolation rules: every entry this area creates has a URL built from t_uniq_host() (wininet<pid>n<k>...),
 * is tracked for DeleteUrlCacheEntryA at exit, and every group created is deleted at exit (ueg_group_track).
 * Enumerations that must be deterministic are filtered by a group the test created (FindFirstUrlCacheEntryEx
 * with GroupId), so foreign cache entries on the box never influence a hard CHECK. */
#ifndef UEG_H
#define UEG_H
#include "t.h"
#include <wininet.h>
#include "tnet.h"

/* --- declarations mingw-w64 lacks (winineti.h / MSDN prototypes; layouts verified against the decomp) --- */
typedef struct {
    DWORD dwCacheVersion;           /* Win10 writes 0x70 here [D ConvertCacheContainerInfoA/W] */
    LPSTR lpszName, lpszCachePrefix, lpszVolumeLabel, lpszVolumeTitle;
} UEG_CONTAINER_INFOA;             /* 0x28 bytes on x64 */
typedef struct {
    DWORD dwCacheVersion;
    LPWSTR lpszName, lpszCachePrefix, lpszVolumeLabel, lpszVolumeTitle;
} UEG_CONTAINER_INFOW;

typedef struct {
    DWORD dwStructSize, dwContainer, dwQuota, dwReserved4, fPerUser, dwSyncMode, dwNumCachePaths;
    CHAR  CachePath[MAX_PATH];
    DWORD dwCacheSize, dwNormalUsage, dwExemptUsage;
} UEG_CONFIG_INFOA;                /* 300 bytes */
typedef struct {
    DWORD dwStructSize, dwContainer, dwQuota, dwReserved4, fPerUser, dwSyncMode, dwNumCachePaths;
    WCHAR CachePath[MAX_PATH];
    DWORD dwCacheSize, dwNormalUsage, dwExemptUsage;
} UEG_CONFIG_INFOW;                /* 0x230 = 560 bytes */

UDECL(HANDLE, FindFirstUrlCacheContainerA, (LPDWORD, UEG_CONTAINER_INFOA *, LPDWORD, DWORD));
UDECL(HANDLE, FindFirstUrlCacheContainerW, (LPDWORD, UEG_CONTAINER_INFOW *, LPDWORD, DWORD));
UDECL(BOOL, FindNextUrlCacheContainerA, (HANDLE, UEG_CONTAINER_INFOA *, LPDWORD));
UDECL(BOOL, FindNextUrlCacheContainerW, (HANDLE, UEG_CONTAINER_INFOW *, LPDWORD));
UDECL(BOOL, CreateUrlCacheContainerA, (LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, LPVOID, LPDWORD));
UDECL(BOOL, CreateUrlCacheContainerW, (LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, LPVOID, LPDWORD));
UDECL(BOOL, DeleteUrlCacheContainerA, (LPCSTR, DWORD));
UDECL(BOOL, DeleteUrlCacheContainerW, (LPCWSTR, DWORD));
UDECL(BOOL, GetUrlCacheConfigInfoA, (UEG_CONFIG_INFOA *, LPDWORD, DWORD));
UDECL(BOOL, GetUrlCacheConfigInfoW, (UEG_CONFIG_INFOW *, LPDWORD, DWORD));
UDECL(BOOL, SetUrlCacheConfigInfoA, (UEG_CONFIG_INFOA *, DWORD));
UDECL(BOOL, SetUrlCacheConfigInfoW, (UEG_CONFIG_INFOW *, DWORD));
UDECL(BOOL, FreeUrlCacheSpaceA, (LPCSTR, DWORD, DWORD));
UDECL(BOOL, FreeUrlCacheSpaceW, (LPCWSTR, DWORD, DWORD));
UDECL(BOOL, IsUrlCacheEntryExpiredA, (LPCSTR, DWORD, FILETIME *));
UDECL(BOOL, IsUrlCacheEntryExpiredW, (LPCWSTR, DWORD, FILETIME *));
UDECL(DWORD, GetUrlCacheEntryBinaryBlob, (LPCWSTR, DWORD *, FILETIME *, FILETIME *, FILETIME *, BYTE **, DWORD *));
UDECL(DWORD, CommitUrlCacheEntryBinaryBlob, (LPCWSTR, DWORD, FILETIME, FILETIME, const BYTE *, DWORD));

/* winineti.h constants */
#define UEG_FIND_ONLY_STRUCT        0x2   /* FIND_FLAGS_RETREIVE_ONLY_STRUCT_INFO: fixed part only, needs >= 0x70 */
#define UEG_FIND_FIXED_AND_FILENAME 0x4   /* FIND_FLAGS_RETREIVE_ONLY_FIXED_AND_FILENAME: needs >= 0x174 */
#define UEG_CC_SYNC_MODE_FC      0x00000080
#define UEG_CC_CONTENT_PATHS_FC  0x00000100
#define UEG_CC_COOKIES_PATHS_FC  0x00000200
#define UEG_CC_HISTORY_PATHS_FC  0x00000400
#define UEG_CC_QUOTA_FC          0x00000800
#define UEG_CC_CONTENT_USAGE_FC  0x00002000
#define UEG_CC_STICKY_USAGE_FC   0x00004000
#define UEG_CC_DISK_CACHE_PATHS_FC 0x00000040
#define UEG_ERROR_NO_NEW_CONTAINERS 12051
#define UEG_FIND_CONTAINER_RETURN_NOCHANGE 0x1
#define UEG_DEFAULT_FILTER (NORMAL_CACHE_ENTRY | COOKIE_CACHE_ENTRY | URLHISTORY_CACHE_ENTRY | TRACK_OFFLINE_CACHE_ENTRY | TRACK_ONLINE_CACHE_ENTRY | STICKY_CACHE_ENTRY)
#define UEG_ENUM_CAP 20000              /* hard bound on any whole-cache enumeration loop */
#define UEG_ENTRY_A_FIXED 0x70          /* sizeof(INTERNET_CACHE_ENTRY_INFOA) on x64 */

/* --- time helpers (all computed inside the guest; day-sized margins) --- */
FILETIME ueg_now(void);
FILETIME ueg_days(int days);           /* now + days (negative = past) */
FILETIME ueg_ft(ULONGLONG v);
ULONGLONG ueg_u64(FILETIME f);

/* --- entries --- */
/* Create + commit an entry for url (A API). body written to the local file (NULL -> "x").
 * Returns 1 on success; the url is tracked for deletion. hdr may be NULL. ext may be NULL. */
int  ueg_make_entry(const char *url, DWORD type, FILETIME expire, FILETIME lastmod, const char *hdr, const char *ext, const char *body);
int  ueg_make_simple(const char *url);                 /* NORMAL, expire +30 d, lastmod -1 d, ext "txt", body "hello" */
const char *ueg_url(const char *tag);                  /* unique http URL, tracked */
/* GetUrlCacheEntryInfoA into a malloc'd buffer (caller frees) or NULL */
INTERNET_CACHE_ENTRY_INFOA *ueg_info_a(const char *url, DWORD *size_out);
int  ueg_exists(const char *url);
DWORD ueg_align4(DWORD n);
DWORD ueg_expected_size_a(const INTERNET_CACHE_ENTRY_INFOA *e);  /* 0x70 + al4(url+1) + al4(file+1) + al4(ext+1) + al4(hdr) */

/* --- enumeration helpers --- */
/* Enumerate with FindFirstUrlCacheEntryExA(pattern, flags, filter, gid) using a growing buffer.
 * For each entry calls cb(info, size, ctx); stops if cb returns 0. Returns the number of entries seen,
 * *last_err gets the error that ended the enumeration (259 normally), -1 if FindFirst failed with err != 259. */
typedef int (*ueg_enum_cb)(const INTERNET_CACHE_ENTRY_INFOA *e, DWORD size, void *ctx);
int  ueg_enum_ex_a(const char *pattern, DWORD flags, DWORD filter, GROUPID gid, ueg_enum_cb cb, void *ctx, DWORD *last_err);
int  ueg_enum_plain_a(const char *pattern, ueg_enum_cb cb, void *ctx, DWORD *last_err);   /* FindFirstUrlCacheEntryA */
/* convenience: does an enumeration see url? count = number of entries total */
int  ueg_enum_contains_a(const char *pattern, DWORD flags, DWORD filter, GROUPID gid, const char *url, int *count);
int  ueg_plain_contains_a(const char *pattern, const char *url_substr, int *count);

/* --- groups --- */
GROUPID ueg_group_new(DWORD flags);    /* CreateUrlCacheGroup + track; 0 on failure */
void ueg_group_track(GROUPID g);
void ueg_group_untrack(GROUPID g);
int  ueg_groups_contains(GROUPID g, int *count);   /* FindFirst/NextUrlCacheGroup sees g */

/* wide helper: a static rotating copy of an ASCII string */
const WCHAR *ueg_w(const char *s);
#endif
