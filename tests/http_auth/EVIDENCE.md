# http_auth - evidence for the expectations

Area prefix `auth_`. Every peer is an in-process loopback server started by the test (`common/srv.h`); no internet,
no proxy/zone/registry change. The proxy tests use a per-session `INTERNET_OPEN_TYPE_PROXY` pointing at a loopback
"proxy" and a fictitious origin `i7origin.invalid` (never resolved).

Oracle: Windows 10 22H2 VM (10.0.19045.2965, wininet 11.0.19041.2193), boots `auth-20261109-171356`,
`auth-20261109-173753` and later (`~/w10lab/runs/auth-*`). Tags used below and in source comments:

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

## Not covered / downgraded
- `InternetSetCredentialsEx` does not exist in Win10 wininet exports; `HttpGetServerCredentials` is internal.
- INTERNET_OPTION_SECONDARY_CACHE_KEY: not applicable to auth.
- Global (NULL-handle) USERNAME/PASSWORD are process-wide and would leak into every later test of the exe; not set.
- Kerberos: no KDC in the lab.
