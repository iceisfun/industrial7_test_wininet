# http_auth - evidence for the expectations

Area prefix `auth_`. Every peer is an in-process loopback server started by the test (`common/srv.h`); no internet,
no proxy/zone/registry change. The proxy tests use a per-session `INTERNET_OPEN_TYPE_PROXY` pointing at a loopback
"proxy" and a fictitious origin `i7origin.invalid` (never resolved).

Oracle: Windows 10 22H2 VM (10.0.19045.2965, wininet 11.0.19041.2193), boots `auth-20261109-171356`,
`auth-20261109-173753`, `auth-20261110-050149` (146 tests), `auth-20261110-051840` (207),
`auth-20261110-065608` (218 tests, 0 failed) and later (`~/w10lab/runs/auth-*`). Tags used below and in source comments:

- **[D]** decomp of the Win10 wininet.dll (docker1 corpus API), function named.
- **[VM]** observed on the Win10 VM and made a hard CHECK (comment `Win10 VM` next to the check).
- **[K]** protocol knowledge (RFCs, NTLM spec) used to build the verifiers; the VM confirmed every one that is a CHECK.
- Anything that is still only `t_note` is recorded behaviour, not an expectation.

## Test servers built for this area (`auth_util.c`)
- **gate**: answers 200 only to an exact expected `Authorization` / `Proxy-Authorization` value, otherwise 401/407
  + the scripted challenge. A 200 therefore proves the client computed the credential exactly.
- **Digest verifier**: recomputes the RFC 2617 response (MD5, MD5-sess, qop=auth or RFC 2069) from the known password
  and the uri/method/nonce/nc/cnonce in the header; the tests recompute it again from the recorded header.
  MD5/MD4/HMAC-MD5 are implemented in the test and checked against RFC 1321/1320/2104/2617 vectors
  (`auth_selftest_md5_md4_hmac`).
- **NTLM server**: fixed server challenge `0123456789abcdef`, type 2 with target info + timestamp, verifies the
  NTLMv2 NTProofStr of the type 3 with the known password (NTOWFv2 over user/domain exactly as sent). This makes
  NTLM success testable without a local account. The real SSPI server side (`S_AUTH`, AcceptSecurityContext) is also
  used, for the unknown-account and default-credential cases.

## Basic (`basic.c`, `edge.c`)
| Expectation | Evidence |
|---|---|
| No credentials: HttpSendRequest TRUE, status 401, body readable, one request | [K] research 02 s10, [VM] |
| WWW-Authenticate queryable by index, ERROR_HTTP_HEADER_NOT_FOUND after the last, small buffer -> 122 with size incl. NUL | [VM] |
| Credentials from InternetConnect, request USERNAME/PASSWORD, InternetConnectW, URL userinfo (percent-decoded), all answer the challenge with exact `Basic base64(user:pass)` on the same keep-alive connection | [VM] |
| User without password, or "" password, or password without user: no retry (401, 1 request) | [D ProcessResponseHeaders: SetUser/SetPass only when both are non-NULL], [VM] |
| InternetConnect credentials take precedence over INTERNET_OPTION_USERNAME/PASSWORD set on the request | [VM] |
| Non-ASCII wide credentials are sent in the ANSI code page (1252 here), not UTF-8 | [VM] (CHECK only when ACP is 1252) |
| Scheme / header name case-insensitive, realm optional or unquoted, Basic picked among unknown schemes; Bearer/unknown/empty/no challenge -> 401 to caller | [D CreateAuthCtxForScheme], [VM] |
| Wrong credentials: exactly one retry, then the 401 is returned | [VM] |
| INTERNET_FLAG_NO_AUTH: no retry, also no pre-authentication | [D research 02 `0x4f4 & 0x40000`], [VM] |
| Caller-supplied Authorization is sent first and replaced on the retry | [VM] |
| POST/PUT body re-sent with the retry; HEAD/DELETE/OPTIONS/PATCH retried | [VM] |
| Request-header view (`HTTP_QUERY_FLAG_REQUEST_HEADERS`) does not contain the Authorization added on the retry | [VM] |
| Retry header order `User-Agent, Host, Cache-Control, Connection, Authorization` | [VM] |
| 401 bodies (chunked, 64 KB, close-delimited, HTTP/1.0) are drained and the retry reuses / reopens the connection | [VM] |
| Redirect then 401: auth on the redirect target; credentials not sent to another host name after a redirect | [VM] |

## Credential cache / pre-authentication (`cache.c`)
All [VM]: after a successful Basic exchange the next request to the same directory (and sub-directories) carries the
header pre-emptively; another or parent directory is challenged again and answered; the cache is process-wide
(new connect handle, new InternetOpen session); a failed pair is remembered and replayed on the next challenge;
a 401 to a pre-authenticated request is returned without another retry. Write-back of credentials happens in
[D AuthOnResponse -> InetSetCachedCredentialsW / PWC flags].

## Digest (`digest.c`, `https_cb.c`)
[K]+[VM]: qop=auth MD5 response verified end-to-end (RFC 2617 example credentials), nc=00000001 unquoted, opaque
echoed, uri = request-target including the query, method in HA2, MD5-sess, RFC 2069 form without qop, qop list ->
auth, stale=true retried with the new nonce without counting as a failure, pre-emptive Digest with nc=00000002 on the
next request, Digest preferred over Basic regardless of order, unsupported algorithm or missing nonce -> one resend
without Authorization then 401 [VM]. Digest is in-process (DIGEST_CTX) [D].

## NTLM / Negotiate (`ntlm.c`)
- Type 1 (explicit credentials): 40 bytes, flags 0xa2088207, version 10.0.19041 [VM]; Type 3 carries an NTLMv2
  response (verified), LM 24 bytes, domain and workstation = computer name when no domain is given, user/domain split
  for `DOMAIN\user`, UPN kept whole with empty domain [VM].
- All legs on one connection; a second request repeats the full anonymous -> type1 -> type3 handshake [VM].
- POST: type-1 leg is sent with Content-Length: 0 and no body [VM].
- Negotiate offered with NTLM: Negotiate is chosen and carries a raw NTLMSSP type 1 (no SPNEGO, workgroup host) [VM].
- Real SSPI server: unknown account -> SEC_E_LOGON_DENIED, the 401 reaches the caller after 3 requests [VM].
  Default credentials: `127.0.0.1` gets no automatic logon (Internet zone), `localhost` logs on as the process user
  (Local Intranet) [VM, default zone settings of the image].

## Proxy (`proxy.c`)
[VM]: absolute-form request line and Host of the origin; 407 returned without proxy credentials;
PROXY_USERNAME/PASSWORD answer `Proxy-Authenticate: Basic`; server credentials (InternetConnect or request
USERNAME/PASSWORD) are used for the proxy leg when present - even over PROXY_* options
([D ProcessResponseHeaders: GetUserPassAndCredentials(0,...) fallback]); proxy credentials are then sent pre-emptively
to any path; NO_AUTH applies to 407; NTLM to a proxy verified with the custom NTLM server.

## Options (`options.c`)
[D InternetQueryOptionA case 0x1c/0x1d/0x2b/0x2c, InternetSetOptionW]: session or NULL handle -> 12018; connect
and request handles hold USERNAME/PASSWORD/PROXY_USERNAME/PROXY_PASSWORD; W set on NULL handle for PROXY_* -> TRUE.
[VM]: A query returns characters without NUL (needs size with NUL on 122), W needs bytes with NUL on 122 and returns
characters on success; empty / NULL / zero-length set -> 87; A set takes the NUL-terminated string regardless of the
length; the request reads through to the connect object; SUPPRESS_SERVER_AUTH settable on request only (12018 on
connect/session), not queryable (87); A set of PROXY_USERNAME on NULL -> 12018.

## InternetErrorDlg (`errordlg.c`)
Only paths that return before any window are used.
[D InternetErrorDlg, LaunchCredUI]: NULL request with 12014/12034/12044 -> 87; 12053 -> 120; credential path with no
hWnd and no NO_UI -> 87; FILTER_FOR_ERRORS maps a 401/407 to 12014.
[VM]: with FLAGS_ERROR_UI_FLAGS_NO_UI and nothing cached the result is 0 (ERROR_CANCELLED folded by LaunchCredUI),
also on 200 requests, session and connect handles; the documented ERROR_INTERNET_FORCE_RETRY needs cached
credentials, which a non-destructive area does not create.

## HttpSendRequestEx / HttpEndRequest (`sendex.c`)
- [D] HttpEndRequestA/W call `HttpWrapSendRequest(..., AR_TYPE 0x12)`, HttpSendRequestExA/W use 0x11. In
  `HTTP_REQUEST_HANDLE_OBJECT::HttpSendRequest_Start` the auth state 0x2f00 (`this+0x1488`) is returned to the caller only
  for AR_TYPE 0x12 and only when NO_AUTH (`0x4f4 & 0x40000`) is clear. HttpSendRequest loops internally instead.
- [VM] With credentials, HttpEndRequest fails with ERROR_INTERNET_FORCE_RETRY (12032) after the 401/407. At that point the
  401 stays the current response: status 401, WWW-Authenticate queryable, body readable. The application re-sends
  (HttpSendRequestEx + InternetWriteFile + HttpEndRequest, or plain HttpSendRequest with the body), and that send carries
  the credentials and the body again. Covered: connect credentials, request option credentials, W entry points, Digest,
  a proxy 407 with PROXY_* options, GET without a body, a body written in two pieces.
- [VM] Without credentials, with NO_AUTH, and for a 407 without proxy credentials, HttpEndRequest returns TRUE with the
  401/407. Wrong credentials give one FORCE_RETRY, then a TRUE completion with 401. NTLM gives two FORCE_RETRYs (type 1 leg,
  then type 3 leg), three requests, and the body on the last one. After a success the credential cache pre-authenticates
  the next Ex request with no FORCE_RETRY. HttpEndRequest without HttpSendRequestEx fails with 12017.

## Auth header queries (`hdrq.c`)
- [VM] HTTP_QUERY_WWW_AUTHENTICATE A: on success the length is in characters without the NUL. A too-small buffer or NULL
  gives 122 with the length including the NUL, and the index is left unchanged. W: lengths in bytes, same rules. A NULL
  index pointer means the first occurrence. Several headers are reachable by index whatever their name casing. A comma
  list is one header. HTTP_QUERY_CUSTOM matches case-insensitively. The challenge appears in RAW_HEADERS(_CRLF). A
  3000-character realm round-trips exactly. Proxy-Authenticate, Authorization and Proxy-Authorization are absent from a
  401 response view (12150).
- [VM] An `Authorization` header passed to HttpSendRequest(A/W) goes on the wire but is **not** kept in the request-header
  view after the send (12150, also missing from RAW_HEADERS_CRLF), like the one wininet adds itself on a retry. Before the
  send, a header added with HttpAddRequestHeaders is visible. ADD then REPLACE sends one header. A caller
  Proxy-Authorization to a direct origin is sent on both legs. Authentication-Info on the 200 is readable through CUSTOM,
  and the 401's WWW-Authenticate is gone after the successful retry. A query before any send gives 12150.

## Credential vectors (`vec.c`)
- [VM] Basic: user/password lengths 1..18 cover every base64 padding class, through InternetConnectA/W and the
  USERNAME/PASSWORD options A/W. Punctuation table (colons, quotes, `%`, `+`, tabs, leading and trailing spaces, 64- and
  200-character values): the exact `base64(user ":" pass)` every time, plus fixed RFC 7617 strings. Bytes >= 0x80 through
  the A API are sent raw (ACP 1252 image; checked only when ACP is 1252).
- [VM] InternetOpenUrl(A/W) userinfo: percent-decoded (`%40 %20 %25 %2F %23 %3F`, encoded letters), `+` kept. User only or
  an empty password: no retry (401, one request). Never pre-emptive on the first request.
- [VM]+[K] Digest variants, each a server-verified MD5 chain: algorithm `md5` or `"MD5"`, a realm with a comma, an empty
  realm, a base64-like nonce, no opaque (none sent back), a domain= list, unquoted qop, qop `auth-int,auth` (auth chosen),
  a percent-escaped uri with a query (uri echoed exactly as the request-target), a password with colons, a user with `@`,
  RFC 2069 PUT, MD5-sess POST, charset=, stale=FALSE, odd whitespace, an upper-case scheme, DELETE.
- [VM] `algorithm=MD5` is echoed only when the challenge named one. The cnonce is 32 lowercase hex characters and is
  reused for the pre-emptive requests (nc 00000002, 00000003). qop=auth-int only, or a SHA-256 Digest challenge listed
  before an MD5 one: one resend without Authorization, then 401. There is no fallback to the second challenge.

## Retry bounds (`retry.c`)
[VM]: a realm that changes on every 401, a 401 without a challenge after the credentialed leg, a 403 after it, Basic
followed by a Digest challenge, a server that wants two credentialed legs: two requests each, and the last response goes
to the caller. A 200 carrying WWW-Authenticate is not retried. **Digest `stale=true` with a fresh nonce is answered
indefinitely:** the client sent 10 Digest legs and the loop ended only at the server's 403 cap. One stale leg moves to the
new nonce with nc=00000001. A 407 from a direct (non-proxy) origin is returned as is, even with PROXY_* options set.
Wrong credentials: 2 legs per HttpSendRequest across 4 requests. 401 + retry + 2 pre-emptive requests use one keep-alive
connection.

## SUPPRESS_SERVER_AUTH (`suppress.c`)
[D InternetSetOptionA case 0x68]: request handles only. It ORs 0x2000 into `+0x149c` without reading the buffer, and fails
with 12019 if `+0x149c & 0x20`. [docs]: "will not logon to origin servers, but will perform automatic logon to HTTP proxy
servers". [VM]: once set, origin authentication is off for that request with any credentials. Default logon to
`localhost` (Intranet, which otherwise logs on, ntlm.c), explicit Basic, Digest and NTLM credentials, and the cached
pre-emptive Basic header are all dropped: 401 and one request with no Authorization. A value of 0 suppresses as well,
since the buffer is not read. Proxy Basic with PROXY_* options is still answered (200). Through a proxy, the origin's 401
is returned. Setting it after the send fails with 12019. The W setter works, and on a connect handle it fails with 12018.

## Environment notes
- Wininet keeps pooled keep-alive sockets after the handles close, and the server library's `shutdown()` does not wake a
  blocked `recv` on Windows. Each `srv_stop` therefore waited 3 s (boot 3: 458 s for 146 tests). The gate and retry
  servers now use a 1 s per-connection io timeout (`gate_start_kind`), which brings it to about 1 s per test.
- The first HTTPS handshake of the process could stall for 5 s with no ClientHello (12030, boots 2-3).
  `auth_https_ntlm_after_warmup` runs first and only records it. After it, NTLM over HTTPS passed.
- InternetErrorDlg NO_UI FORCE_RETRY: [D InetGetCachedCredentialsW] reads Credential Manager entries
  `Microsoft_WinInet_<host>:<port>/<realm>` (persistent), so a non-destructive area cannot set it up.

## Not covered / downgraded
- `InternetSetCredentialsEx` does not exist in Win10 wininet exports; `HttpGetServerCredentials` is internal.
- INTERNET_OPTION_SECONDARY_CACHE_KEY: not applicable to auth.
- Global (NULL-handle) USERNAME/PASSWORD are process-wide and would leak into every later test of the exe; not set.
- Kerberos: no KDC in the lab.
