# http_cache_integration: evidence

Area: how WinINet HTTP requests interact with the URL cache. There are about 250 tests in 10 files (`hci_*.c`) with
helpers in `hci.h`, `hci_util.c` and `hci_wait.c`. Every test starts its own loopback server and uses unique URLs
(`wininet_<pid>_<n>_<tag>` on an ephemeral port). Every entry is registered with `t_cache_track` and deleted at exit,
and cookies are not written (`NO_COOKIES` where a response sets one).

Oracle: Windows 10 22H2 (`ver` 10.0.19045.2965, wininet 11.0.19041.2193), local QEMU guest via `tools/vm_run.sh`.
Decomp: the Corpus Explorer, wininet.dll 10.0.19041 (`/api/function/wininet/<rva>/decomp`).

Labels used below:
- **D**: the expectation was derived from the decompilation before the VM run, and the VM confirmed it.
- **V**: the expectation was observed on the VM (a `t_note` first, promoted to a CHECK after it held). Where the decomp
  explains it, that is noted.
- **K**: the expectation comes from knowledge of WinINet only. Very few of these remain as hard CHECKs, and each one
  also passed on the VM.

Anything that varies from one boot to the next, such as timing, file subdirectory names, or 1-second max-age races, stays a `t_note`.

## Decompiled functions used
| Function (RVA) | Used for |
|---|---|
| `GetCacheTimeStampsFromHeaders` 0x6bd80 | ExpireTime/LastModifiedTime from Cache-Control, Age, Date, Expires, Last-Modified |
| `IsExpired` 0xc7d88 | freshness: FWD_BACK, Expire vs now, heuristic `(sync-LM)/10`, HYPERLINK + no LM, session rule |
| `GetFromCachePreNetIoLoop` 0x87140 | the lookup: type/partition match, redirect entries need ENABLE_REDIRECT_CACHE_READ, conditional headers, sparse resume (`Range: bytes=N-` + If-Range) |
| `FAddIfModifiedSinceHeader` 0x21a3c | IMS = RFC 1123 of the entry's LastModifiedTime, with `; length=N` unless entry type bit 0x40 |
| `AddHeaderIfEtagFound` 0x12254 | If-None-Match from the stored blob only when type bit 0x40; 0x200 buffer |
| `FCanWriteToCache` 0x6a120 | 200/redirect rules, POST needs a secondary key, no-store/HTTP 0.9 delete except with a WebDAV `Translate` header, HTTPS + Pragma |
| `LocalEndCacheWrite` 0xe6c0 | entry flags (0x800 redirect, 0x10000 sparse), blob generation |
| `FHttpBeginCacheRetrieval` | entry/handle partition bits must match |

## Findings by topic

### Entry written by a GET (`hci_store.c`, `hci_api.c`)
- V: the type is `0x41` (NORMAL_CACHE_ENTRY plus bit 0x40, which marks an HTTP-written entry). `dwHitRate` is 1 and `dwUseCount` is 0 after the
  download. `lpszFileExtension` is empty. The local file is `...\INetCache\IE\<8 chars>\<leaf>[1].<ext>`.
- V: the blob is exact. `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n` keeps the server
  header order and casing, and `dwHeaderInfoSize` equals `strlen`.
- V: the blob filter (`hci_api_blob_kept_headers_table`) drops Cache-Control, Last-Modified, Expires, Date, Server, Age,
  Set-Cookie, Accept-Ranges and Proxy-Connection. It keeps ETag, Pragma, Vary, Set-Cookie2, Keep-Alive, P3P, STS, X-Frame-Options,
  WWW-Authenticate, Content-Language/Location/Disposition, Location, Refresh, Link and X-*. Transfer-Encoding is kept for a
  chunked body. A close-delimited body gets no invented Content-Length.
- V: the file extension comes from a known Content-Type (`text/html` gives htm, and so on, 14 rows). Octet-stream or no type keeps
  the URL's extension, with its case (`.TXT`). `name.tar.gz` gives `name.tar[1].gz`. No extension gives `name[1]`, a trailing `/` with
  text/html gives `name[1].htm`, the query is dropped, `%20` is kept literally, and Content-Disposition `filename=` names the file.
- V: two URLs with the same leaf get the same `<leaf>[1].txt` name in different subdirectories. A refetch gets a new file,
  and the old one is removed.
- D/V: statuses other than 200 and the cacheable redirects are not written, even with NEED_FILE. A truncated body or an early close
  commits nothing.

### Expiry computation (`hci_expiry.c`)
- D: `max-age=N` gives ExpireTime = now + (N - age), where age = max(Age, now - Date). A value under 1 gives now - 3600 s.
  N is clamped to 0x7fffffff. Spaces or tab around `=` and any case are accepted. stale-while-revalidate is added to a positive
  max-age. `no-cache` (also `no-cache="..."`) gives now - 3600 s. Tokens are processed in order, so `no-cache, max-age=600` gives +600,
  and `max-age=600, no-cache` gives -3600.
- V: `max-age=abc` gives now - 3600 (stale). Bare `max-age`, `nocache`, `no-cachex`, `s-maxage`, `immutable` and `must-revalidate` alone give
  ExpireTime 0. `pre-check=600, post-check=300` gives +600. `must-revalidate` sets entry type bit 0x100 (`0x141`).
- D: if Expires is <= Date, the expiry is now - 3600 s. If it is later than Date, the header value is stored as is, with no skew correction.
- V: Expires parsing accepts RFC 1123, RFC 850 (2-digit year 33 -> 2033), asctime, lower case, no `GMT`, `UTC` and a 1-digit
  day. An unparsable value (`garbage`, `0`, `-1`, empty) is stored as about "now" and is stale. The first of two Expires headers wins.
- V: an unparsable Last-Modified is stored as about "now", and its If-Modified-Since is then about now too.

### Freshness decisions (`hci_expiry.c`, `hci_fresh.c`, `hci_seed.c`)
- D: `INTERNET_FLAG_FWD_BACK` (0x20) serves any entry: expired, no-cache, or with a past ExpireTime.
- D: ExpireTime set through `SetUrlCacheEntryInfo` decides (7 offsets). The `no-cache` directive is not remembered, because only the times count.
- D: with LM and no Expires, the entry is fresh iff now <= sync + (sync - LM)/10 (7 sync offsets, LM = now - 100 d). With LastSyncTime before
  the session start, an entry without validators is stale. HYPERLINK with no LM is expired, but an LM set through the API makes the heuristic apply.
- D: If-Modified-Since uses the entry's LastModifiedTime, so a value set through the API is what goes on the wire.
- V: a cache hit leaves LastSyncTime alone and adds 1 to the hit rate. RELOAD and a 304 refresh LastSyncTime. A bare 304 keeps the old
  ExpireTime, so the next GET is conditional again.

### Conditional requests and 304 (`hci_cond.c`, `hci_fresh.c`)
- V: the header order is User-Agent, Host, If-Modified-Since, If-None-Match. ETags are copied verbatim (10 forms). An ETag of up to 511
  characters is sent, and a longer one is dropped (D: 0x200 buffer).
- D: an entry of type 1 (API-committed) never sends If-None-Match, and its IMS carries `; length=<size>`. Type 0x41 sends INM and a bare IMS.
  Clearing bit 0x40 with `SetUrlCacheEntryInfo(CACHE_ENTRY_ATTRIBUTE_FC)` switches an HTTP entry to the type-1 behaviour.
- V: after a 304 the app sees 200 OK, `INTERNET_REQFLAG_FROM_CACHE`, the stored length and type, and the stored body. New headers
  are merged and replace stored values (X-*), but a new ETag and Content-Type are not taken. `no-store` on a 304 does not delete the entry.
  Each 304 adds 1 to the hit rate, and the local file is reused.
- V: a conditional request answered with 404 or 410 deletes the entry. 412 and 500 keep it. The app sees the status.
- V: an app-supplied If-None-Match or If-Modified-Since makes the request the app's own. It is sent alone, the cache is bypassed even
  when fresh, and the 304 reaches the app.
- V: NO_CACHE_WRITE and PRAGMA_NOCACHE requests over a stale entry are still conditional. PRAGMA_NOCACHE adds `Cache-Control: no-cache`.

### Request flags (`hci_flags.c`)
- V: only RELOAD and PRAGMA_NOCACHE add `Cache-Control: no-cache`, and no flag adds Pragma. PRAGMA_NOCACHE does not bypass a fresh entry.
- D/V: FROM_CACHE or an OFFLINE session miss fails with ERROR_FILE_NOT_FOUND. FROM_CACHE wins over RELOAD. A stale entry is served offline.
- V: CACHE_IF_NET_FAIL serves the entry with reqflags 0x81 (FROM_CACHE | NET_TIMEOUT). Without an entry the error is ERROR_FILE_NOT_FOUND,
  not CANNOT_CONNECT.
- V: before the send, INTERNET_OPTION_REQUEST_FLAGS answers 8 (NO_HEADERS) for every verb and flag combination.
- V: NO_CACHE_WRITE reads a fresh entry. HEAD with FROM_CACHE gets ERROR_FILE_NOT_FOUND. FORMS_SUBMIT changes nothing for a fresh GET.

### Methods, keys, redirects, Vary, HTTPS (`hci_misc.c`, `hci_extra.c`, `hci_more.c`)
- D/V: POST is cached only under a secondary key (the entry URL is URL + key, and the file name contains the key). The same key serves a later
  POST and FROM_CACHE. HEAD never reads the GET entry.
- V: before the send, INTERNET_OPTION_URL is URL + the first key, with the default port omitted (`http://127.0.0.1/xabc`).
- D/V: 301 and 308 are cached as type 0x841 with ExpireTime 0x7fff... 302, 303 and 307 are cached only with max-age or Expires, and no-cache or no-store
  prevent it. A cached redirect is only followed with `INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ` = 1. That option is set-only:
  a query gives 87, and a NULL handle gives 12018.
- V: `GetUrlCacheEntryInfoEx` with a non-NULL lpszRedirectUrl returns 87.
- V: `Vary: *` and `Vary: Cookie` are never stored. Any other Vary is stored and served.
- V: HTTPS. max-age, public, private or no cache headers are stored, while no-store and `Pragma: no-cache` are not (D: FCanWriteToCache). A stored HTTPS entry is
  **not served** to a request made with SECURITY_FLAG_IGNORE_UNKNOWN_CA (the only way to reach the self-signed loopback server).
  The request goes to the network, and FROM_CACHE misses with 2. The cause is not pinned down in the decomp. It could be the
  certificate-error state of the request. Re-check on a box with a trusted certificate.
- D: no-store over an existing entry deletes it, unless the request carries `Translate: f`
  (`IsWebDAVTranslateHeaderPresent`).

### Content encoding (`hci_misc.c`, `hci_more.c`)
- V: with HTTP_DECODING on, the cache file holds the decoded body (gzip, x-gzip, raw deflate). Content-Encoding is dropped from
  the blob, and the cache hit returns the same bytes, also to a later session with decoding off. With decoding off, the compressed bytes and
  Content-Encoding are stored.
- V: a zlib-wrapped `deflate` body with decoding on is **not** decoded. The app reads 0 bytes, and the entry is not served again.

### Unsafe methods, URL keys, callbacks (`hci_more.c`)
- V: after a POST, PUT, DELETE or PATCH to a URL, its GET entry still exists but the next GET goes to the network.
- V: a 303 after POST is never cached, keyed or not. The GET target is cached.
- V: the host is lower-cased in the key (`LOCALHOST` hits the `localhost` entry). The path, query (`?`), and `%7E` vs `~` are kept verbatim
  (separate entries). Userinfo is dropped from the key and from INTERNET_OPTION_URL, and no Authorization is sent unprompted.
- V: an app-supplied `Authorization` header does not stop caching. A 206 to an app Range request is not cached.
- V: FROM_CACHE follows a cached 301 to its cached target. RELOAD on an OFFLINE session still misses with 2. ENABLE_REDIRECT_CACHE_READ
  reads a whole cached 301 chain.
- V: SECONDARY_CACHE_KEY: an empty key gives 87. A key set after the send is still used. The W set takes characters, and the W query returns characters.
- V: the status callbacks of a cache hit are exactly HANDLE_CREATED (60) then HANDLE_CLOSING (70). A network GET also shows
  DETECTING_PROXY (80), CONNECTING/CONNECTED, SENDING/SENT and RECEIVING/RECEIVED.

### Data file, locks, use counts (`hci_misc.c`, `hci_api.c`)
- V: DATAFILE_NAME is available right after the send. On failure the A form needs strlen+1 and the W form needs bytes including the NUL. On success
  both give characters. On a request that writes nothing (NO_CACHE_WRITE, POST without a key, 404) it fails with 12028.
- V: while downloading, the cache file can be opened with full sharing but not with read-only sharing (32). An open cache-read handle
  gives use count 1 (2 with two handles). DeleteUrlCacheEntry then fails with 32, and the delete happens at the last close.
- V: `InternetLockRequestFile` works before or after reading and on cache hits. It does not count as a use. The entry can be deleted while
  locked, but the file stays until `InternetUnlockRequestFile`. It fails with 2 on NO_CACHE_WRITE or unsent requests, and with 6 on session or connect handles.
- V: an interrupted download (Accept-Ranges + ETag) leaves no visible entry, but the next GET sends `Range: bytes=<n>-` and
  `If-Range: "<etag>"` (D: sparse path of GetFromCachePreNetIoLoop).
- V: CACHE_TIMESTAMPS succeeds on network and cache handles and returns length 0. A wrong length gives 12010, not the 122 that
  docs/research/02 predicted. CACHE_STREAM_HANDLE fails with 122 on a cache hit and with 1 on NO_CACHE_WRITE.
- V: SetFilePointer on a cache handle refuses negative distances with ERROR_NEGATIVE_SEEK. On a NO_CACHE_WRITE handle it fails with 12016.
- V: SetUrlCacheEntryInfo(HEADERINFO_FC) succeeds but does not change what a cache hit returns. A CommitUrlCacheEntry over an HTTP
  entry does replace it.

## Knowledge-only (K) and notes
- The status-callback tests check only that no SENDING_REQUEST, CONNECTING or RECEIVING callback happens on a cache hit, and that HANDLE_CREATED and CLOSING do (K, VM-checked).
- The following stay `t_note` only: the 1-second max-age race, `Expires: 0` and similar stored values, the access-time movement on a hit, and the
  absolute Range offset of a resumed download (it depends on how much the client buffered).

## Environment
- The lab image has no proxy and no autodetect, `SecureProtocols=0x800`, and `CertificateRevocation=1`. Defender and the firewall did not interfere.
- Runtime is about 160 s per area on the VM (VM_TIMEOUT 420).

## VM boots (this pass)
| Boot | Build | Result | Triage |
|---|---|---|---|
| prev pass boot 2 (`hci-20261109-183254`) | 139 tests | 5 failed / 785 checks | gzip stored decoded, HTTPS hit, CACHE_TIMESTAMPS len, IF_NET_FAIL error, REQUEST_FLAGS before send: fixed from observation |
| 1 (`hci4-20261110-051521`) | 223 tests | 5 failed, 1911/1928 checks | LM stripped from blob, unparsable LM/max-age, must-revalidate bit 0x100, InfoEx 87, request-file lock semantics |
| 2 (`hci5-20261110-065037`) | 250 tests | 3 failed, 2214/2224 checks | unsafe methods invalidate GET, zlib deflate not decoded, callbacks, URL keys |
| 3 (`hci6-20261110-084136`) | 250 tests | 1 failed, 2287/2290 checks | `hci_misc_https_cache_hit`: the first TLS request of the test never reached the server (environment), retried once now |
| 4 (`hci8-...`) | final | see below | |
