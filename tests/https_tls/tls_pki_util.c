/* tls_pki_util.c - certificate factory (root CA, leaves, CRLs) and a minimal schannel HTTPS server.
 * See tls_pki.h. Uses the runtime-resolved winsock / SSPI tables of the shared server library (common/srv_int.h:
 * SWS, SSP), crypt32 through U(). Nothing is import-linked and nothing is added to a certificate store. */
#include "tls_pki.h"
#include "srv_int.h"
#include "modules.h"

/* ------------------------------------------------------------------ certificate factory */
#define PKI_MAX 96
static pki_ent g_ents[PKI_MAX];
static LONG g_nents;
static HCERTSTORE g_stores[64];
static PCCERT_CONTEXT g_srvcerts[64];
static LONG g_nstores;
static CRITICAL_SECTION g_pki_cs;
static INIT_ONCE g_pki_once = INIT_ONCE_STATIC_INIT;

static void pki_cleanup(void) {
    for (LONG i = 0; i < g_nstores && i < 64; i++) {
        if (g_srvcerts[i]) U(CertFreeCertificateContext)(g_srvcerts[i]);
        if (g_stores[i]) U(CertCloseStore)(g_stores[i], 0);
    }
    for (LONG i = 0; i < g_nents && i < PKI_MAX; i++) {
        pki_ent *e = &g_ents[i];
        if (e->cert) U(CertFreeCertificateContext)(e->cert);
        if (e->prov) CryptReleaseContext(e->prov, 0);
        if (e->container[0]) { HCRYPTPROV hp; CryptAcquireContextW(&hp, e->container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET); }
    }
}
static BOOL CALLBACK pki_once(PINIT_ONCE o, PVOID p, PVOID *c) { InitializeCriticalSection(&g_pki_cs); atexit(pki_cleanup); return TRUE; }

static void ft_days(FILETIME *ft, int days) {
    ULARGE_INTEGER u; GetSystemTimeAsFileTime(ft);
    u.LowPart = ft->dwLowDateTime; u.HighPart = ft->dwHighDateTime;
    u.QuadPart += (LONGLONG)days * 86400LL * 10000000LL;
    ft->dwLowDateTime = u.LowPart; ft->dwHighDateTime = u.HighPart;
}
static const char *hash_oid(int h) {
    switch (h) { case PKI_SHA1: return szOID_RSA_SHA1RSA; case PKI_MD5: return szOID_RSA_MD5RSA; case PKI_SHA384: return szOID_RSA_SHA384RSA; }
    return szOID_RSA_SHA256RSA;
}

/* parse "dns:x,ip4:a.b.c.d,ip6:::1,url:..." into alt-name entries (static storage per call) */
typedef struct { CERT_ALT_NAME_ENTRY e[8]; WCHAR w[8][128]; BYTE ip[8][16]; int n; } alt_buf;
static int parse_alt(const char *list, alt_buf *b) {
    b->n = 0;
    const char *p = list;
    while (p && *p && b->n < 8) {
        const char *q = strchr(p, ','); size_t len = q ? (size_t)(q - p) : strlen(p);
        char item[160]; if (len >= sizeof item) len = sizeof item - 1; memcpy(item, p, len); item[len] = 0;
        CERT_ALT_NAME_ENTRY *e = &b->e[b->n]; memset(e, 0, sizeof *e);
        if (!strncmp(item, "dns:", 4)) {
            MultiByteToWideChar(CP_ACP, 0, item + 4, -1, b->w[b->n], 128);
            e->dwAltNameChoice = CERT_ALT_NAME_DNS_NAME; e->pwszDNSName = b->w[b->n];
        } else if (!strncmp(item, "ip4:", 4)) {
            unsigned a, c, d, f; if (sscanf(item + 4, "%u.%u.%u.%u", &a, &c, &d, &f) != 4) return 0;
            b->ip[b->n][0] = (BYTE)a; b->ip[b->n][1] = (BYTE)c; b->ip[b->n][2] = (BYTE)d; b->ip[b->n][3] = (BYTE)f;
            e->dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS; e->IPAddress.cbData = 4; e->IPAddress.pbData = b->ip[b->n];
        } else if (!strncmp(item, "ip6:", 4)) {   /* only "::1" is needed */
            memset(b->ip[b->n], 0, 16); b->ip[b->n][15] = 1;
            e->dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS; e->IPAddress.cbData = 16; e->IPAddress.pbData = b->ip[b->n];
        } else if (!strncmp(item, "url:", 4)) {
            MultiByteToWideChar(CP_ACP, 0, item + 4, -1, b->w[b->n], 128);
            e->dwAltNameChoice = CERT_ALT_NAME_URL; e->pwszURL = b->w[b->n];
        } else return 0;
        b->n++;
        p = q ? q + 1 : NULL;
    }
    return 1;
}

static int enc(LPCSTR type, const void *v, BYTE **out, DWORD *n) {
    *n = 0; *out = NULL;
    if (!U(CryptEncodeObject)(X509_ASN_ENCODING, type, v, NULL, n)) return 0;
    *out = malloc(*n);
    return U(CryptEncodeObject)(X509_ASN_ENCODING, type, v, *out, n);
}

pki_ent *pki_make(const pki_spec *sp, pki_ent *issuer) {
    if (!U(CryptSignAndEncodeCertificate) || !U(CryptExportPublicKeyInfo) || !U(CertStrToNameA) || !U(CertCreateCertificateContext)) return NULL;
    InitOnceExecuteOnce(&g_pki_once, pki_once, NULL, NULL);
    EnterCriticalSection(&g_pki_cs);
    LONG idx = g_nents < PKI_MAX ? g_nents++ : -1;
    LeaveCriticalSection(&g_pki_cs);
    if (idx < 0) return NULL;
    pki_ent *e = &g_ents[idx]; memset(e, 0, sizeof *e);
    swprintf(e->container, 64, L"%hs_%lu_pki%ld", T_TMP_PREFIX, GetCurrentProcessId(), idx);
    if (!CryptAcquireContextW(&e->prov, e->container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET) &&
        !CryptAcquireContextW(&e->prov, e->container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, 0)) { e->container[0] = 0; return NULL; }
    HCRYPTKEY key; DWORD bits = sp->bits ? (DWORD)sp->bits : 2048;
    if (!CryptGenKey(e->prov, AT_KEYEXCHANGE, (bits << 16) | CRYPT_EXPORTABLE, &key)) return NULL;
    CryptDestroyKey(key);

    BYTE name[512]; DWORD nl = sizeof name;
    if (!U(CertStrToNameA)(X509_ASN_ENCODING, sp->subject, CERT_X500_NAME_STR, NULL, name, &nl, NULL)) return NULL;
    BYTE pkbuf[1024]; DWORD pkl = sizeof pkbuf;
    if (!U(CryptExportPublicKeyInfo)(e->prov, AT_KEYEXCHANGE, X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)pkbuf, &pkl)) return NULL;

    static LONG serial_n;
    DWORD sn = (DWORD)InterlockedIncrement(&serial_n), pid = GetCurrentProcessId(), tk = GetTickCount();
    e->serial[0] = (BYTE)sn; e->serial[1] = (BYTE)(sn >> 8); e->serial[2] = (BYTE)tk; e->serial[3] = (BYTE)(tk >> 8);
    e->serial[4] = (BYTE)pid; e->serial[5] = (BYTE)(pid >> 8); e->serial[6] = (BYTE)(pid >> 16); e->serial[7] = 0x51;  /* positive */

    CERT_EXTENSION ext[8]; int next = 0; BYTE *bufs[8] = { 0 }; DWORD lens[8];
    alt_buf ab;
    if (sp->san) {
        if (!parse_alt(sp->san, &ab)) return NULL;
        CERT_ALT_NAME_INFO an = { (DWORD)ab.n, ab.e };
        if (enc(X509_ALTERNATE_NAME, &an, &bufs[next], &lens[next])) { ext[next].pszObjId = szOID_SUBJECT_ALT_NAME2; ext[next].fCritical = FALSE; next++; }
    }
    if (sp->eku) {
        LPSTR ids[2]; DWORD ni = 0;
        switch (sp->eku) {
            case PKI_EKU_SERVER: ids[ni++] = szOID_PKIX_KP_SERVER_AUTH; break;
            case PKI_EKU_CLIENT: ids[ni++] = szOID_PKIX_KP_CLIENT_AUTH; break;
            case PKI_EKU_BOTH: ids[ni++] = szOID_PKIX_KP_SERVER_AUTH; ids[ni++] = szOID_PKIX_KP_CLIENT_AUTH; break;
            case PKI_EKU_ANY: ids[ni++] = "2.5.29.37.0"; break;
            case PKI_EKU_CODESIGN: ids[ni++] = szOID_PKIX_KP_CODE_SIGNING; break;
        }
        CERT_ENHKEY_USAGE u = { ni, ids };
        if (enc(X509_ENHANCED_KEY_USAGE, &u, &bufs[next], &lens[next])) { ext[next].pszObjId = szOID_ENHANCED_KEY_USAGE; ext[next].fCritical = FALSE; next++; }
    }
    if (sp->ca) {
        CERT_BASIC_CONSTRAINTS2_INFO bc = { TRUE, FALSE, 0 };
        if (enc(X509_BASIC_CONSTRAINTS2, &bc, &bufs[next], &lens[next])) { ext[next].pszObjId = szOID_BASIC_CONSTRAINTS2; ext[next].fCritical = TRUE; next++; }
    }
    BYTE ku = sp->ca ? 0x86 : sp->ku;
    if (ku) {
        CRYPT_BIT_BLOB kb = { 1, &ku, 0 };
        if (enc(X509_KEY_USAGE, &kb, &bufs[next], &lens[next])) { ext[next].pszObjId = szOID_KEY_USAGE; ext[next].fCritical = TRUE; next++; }
    }
    if (sp->cdp) {
        WCHAR wu[256]; MultiByteToWideChar(CP_ACP, 0, sp->cdp, -1, wu, 256);
        CERT_ALT_NAME_ENTRY ue; memset(&ue, 0, sizeof ue); ue.dwAltNameChoice = CERT_ALT_NAME_URL; ue.pwszURL = wu;
        CRL_DIST_POINT dp; memset(&dp, 0, sizeof dp);
        dp.DistPointName.dwDistPointNameChoice = CRL_DIST_POINT_FULL_NAME; dp.DistPointName.FullName.cAltEntry = 1; dp.DistPointName.FullName.rgAltEntry = &ue;
        CRL_DIST_POINTS_INFO di = { 1, &dp };
        if (enc(X509_CRL_DIST_POINTS, &di, &bufs[next], &lens[next])) { ext[next].pszObjId = szOID_CRL_DIST_POINTS; ext[next].fCritical = FALSE; next++; }
    }
    if (sp->aia) {
        WCHAR wu[256]; MultiByteToWideChar(CP_ACP, 0, sp->aia, -1, wu, 256);
        CERT_ACCESS_DESCRIPTION ad; memset(&ad, 0, sizeof ad);
        ad.pszAccessMethod = szOID_PKIX_CA_ISSUERS; ad.AccessLocation.dwAltNameChoice = CERT_ALT_NAME_URL; ad.AccessLocation.pwszURL = wu;
        CERT_AUTHORITY_INFO_ACCESS ai = { 1, &ad };
        if (enc(X509_AUTHORITY_INFO_ACCESS, &ai, &bufs[next], &lens[next])) { ext[next].pszObjId = szOID_AUTHORITY_INFO_ACCESS; ext[next].fCritical = FALSE; next++; }
    }
    for (int i = 0; i < next; i++) { ext[i].Value.cbData = lens[i]; ext[i].Value.pbData = bufs[i]; }

    CERT_INFO ci; memset(&ci, 0, sizeof ci);
    ci.dwVersion = CERT_V3;
    ci.SerialNumber.cbData = 8; ci.SerialNumber.pbData = e->serial;
    ci.SignatureAlgorithm.pszObjId = (LPSTR)hash_oid(sp->hash);
    ci.Subject.cbData = nl; ci.Subject.pbData = name;
    if (issuer) ci.Issuer = issuer->cert->pCertInfo->Subject; else ci.Issuer = ci.Subject;
    ft_days(&ci.NotBefore, sp->nb_days); ft_days(&ci.NotAfter, sp->na_days);
    ci.SubjectPublicKeyInfo = *(PCERT_PUBLIC_KEY_INFO)pkbuf;
    ci.cExtension = (DWORD)next; ci.rgExtension = ext;
    CRYPT_ALGORITHM_IDENTIFIER alg; memset(&alg, 0, sizeof alg); alg.pszObjId = (LPSTR)hash_oid(sp->hash);
    HCRYPTPROV signer = issuer ? issuer->prov : e->prov;
    DWORD cl = 0; BYTE *der = NULL; int ok = 0;
    if (U(CryptSignAndEncodeCertificate)(signer, AT_KEYEXCHANGE, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &ci, &alg, NULL, NULL, &cl)) {
        der = malloc(cl);
        ok = U(CryptSignAndEncodeCertificate)(signer, AT_KEYEXCHANGE, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &ci, &alg, NULL, der, &cl);
    }
    for (int i = 0; i < next; i++) free(bufs[i]);
    if (!ok) { t_note("pki: sign failed for %s: %lu", sp->subject, GetLastError()); free(der); return NULL; }
    e->cert = U(CertCreateCertificateContext)(X509_ASN_ENCODING, der, cl);
    free(der);
    return e->cert ? e : NULL;
}

pki_ent *pki_root(void) {
    static pki_ent *root; static int tried;
    InitOnceExecuteOnce(&g_pki_once, pki_once, NULL, NULL);
    EnterCriticalSection(&g_pki_cs);
    int t = tried; tried = 1;
    LeaveCriticalSection(&g_pki_cs);
    if (!t) {
        char subj[96]; snprintf(subj, sizeof subj, "CN=i7 Test Root %lu, O=i7 wininet corpus", GetCurrentProcessId());
        pki_spec sp; memset(&sp, 0, sizeof sp);
        sp.subject = subj; sp.nb_days = -2; sp.na_days = 60; sp.ca = 1;
        root = pki_make(&sp, NULL);
    }
    return root;
}

BYTE *pki_crl(pki_ent *ca, pki_ent **revoked, int nrev, int next_days, DWORD *len) {
    CRL_ENTRY ent[8]; if (nrev > 8) nrev = 8;
    for (int i = 0; i < nrev; i++) {
        memset(&ent[i], 0, sizeof ent[i]);
        ent[i].SerialNumber.cbData = 8; ent[i].SerialNumber.pbData = revoked[i]->serial;
        ft_days(&ent[i].RevocationDate, -1);
    }
    CRL_INFO ci; memset(&ci, 0, sizeof ci);
    ci.dwVersion = CRL_V2;
    ci.SignatureAlgorithm.pszObjId = szOID_RSA_SHA256RSA;
    ci.Issuer = ca->cert->pCertInfo->Subject;
    ft_days(&ci.ThisUpdate, -1); ft_days(&ci.NextUpdate, next_days);
    ci.cCRLEntry = (DWORD)nrev; ci.rgCRLEntry = ent;
    CRYPT_ALGORITHM_IDENTIFIER alg; memset(&alg, 0, sizeof alg); alg.pszObjId = szOID_RSA_SHA256RSA;
    DWORD n = 0;
    if (!U(CryptSignAndEncodeCertificate)(ca->prov, AT_KEYEXCHANGE, X509_ASN_ENCODING, X509_CERT_CRL_TO_BE_SIGNED, &ci, &alg, NULL, NULL, &n)) return NULL;
    BYTE *b = malloc(n);
    if (!U(CryptSignAndEncodeCertificate)(ca->prov, AT_KEYEXCHANGE, X509_ASN_ENCODING, X509_CERT_CRL_TO_BE_SIGNED, &ci, &alg, NULL, b, &n)) { free(b); return NULL; }
    *len = n; return b;
}

PCCERT_CONTEXT pki_server_cert(pki_ent *leaf, pki_ent **chain, int nchain) {
    if (!leaf || !U(CertOpenStore) || !U(CertAddCertificateContextToStore) || !U(CertSetCertificateContextProperty)) return NULL;
    HCERTSTORE st = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    if (!st) return NULL;
    PCCERT_CONTEXT in = NULL;
    if (!U(CertAddCertificateContextToStore)(st, leaf->cert, CERT_STORE_ADD_ALWAYS, &in)) { U(CertCloseStore)(st, 0); return NULL; }
    for (int i = 0; i < nchain; i++) if (chain[i]) U(CertAddCertificateContextToStore)(st, chain[i]->cert, CERT_STORE_ADD_ALWAYS, NULL);
    CRYPT_KEY_PROV_INFO kpi; memset(&kpi, 0, sizeof kpi);
    kpi.pwszContainerName = leaf->container; kpi.pwszProvName = MS_ENH_RSA_AES_PROV_W; kpi.dwProvType = PROV_RSA_AES; kpi.dwKeySpec = AT_KEYEXCHANGE;
    U(CertSetCertificateContextProperty)(in, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi);
    EnterCriticalSection(&g_pki_cs);
    LONG i = g_nstores < 64 ? g_nstores++ : -1;
    if (i >= 0) { g_stores[i] = st; g_srvcerts[i] = in; }
    LeaveCriticalSection(&g_pki_cs);
    return in;
}

const char *pki_simple_name(PCCERT_CONTEXT c, int issuer) {
    static char b[4][256]; static LONG n;
    char *o = b[InterlockedIncrement(&n) & 3]; o[0] = 0;
    if (c && U(CertNameToStrA)) U(CertNameToStrA)(X509_ASN_ENCODING, issuer ? &c->pCertInfo->Issuer : &c->pCertInfo->Subject,
                                                  CERT_SIMPLE_NAME_STR | CERT_NAME_STR_CRLF_FLAG | CERT_NAME_STR_NO_PLUS_FLAG, o, 256);
    return o;
}

/* ------------------------------------------------------------------ minimal schannel HTTPS server */
struct mts {
    SOCKET ls; unsigned short port; HANDLE stop, thr;
    CredHandle cred; int have_cred;
    CRITICAL_SECTION cs;
    mts_conn rec[MTS_MAXC]; HANDLE cthr[MTS_MAXC]; SOCKET csock[MTS_MAXC];
    volatile LONG nconn, nfinished, nreq;
};
typedef struct { mts *m; int id; } mts_arg;

#define MTS_ASC (ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM)

static int mts_send_all(SOCKET s, const void *p, size_t n) {
    const char *b = p;
    while (n) { int k = SWS.send(s, b, (int)n, 0); if (k <= 0) return -1; b += k; n -= k; }
    return 0;
}

static DWORD WINAPI mts_conn_thread(LPVOID p) {
    mts_arg *a = p; mts *m = a->m; int id = a->id; free(a);
    mts_conn *r = &m->rec[id]; SOCKET s = m->csock[id];
    DWORD to = 5000;
    SWS.setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof to);
    SWS.setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&to, sizeof to);
    size_t cap = 65536, nraw = 0; char *raw = malloc(cap);
    CtxtHandle ctx; int have_ctx = 0; SECURITY_STATUS st = SEC_I_CONTINUE_NEEDED; ULONG attr; TimeStamp ts;
    for (int rounds = 0; (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_INCOMPLETE_MESSAGE) && rounds < 24; rounds++) {
        if (nraw == 0 || st == SEC_E_INCOMPLETE_MESSAGE) {
            if (nraw >= cap) break;
            int k = SWS.recv(s, raw + nraw, (int)(cap - nraw), 0);
            if (k <= 0) { st = (SECURITY_STATUS)0xEEEE0000 | (k == 0 ? 1 : 2); break; }
            nraw += k;
        }
        SecBuffer ib[2] = { { (ULONG)nraw, SECBUFFER_TOKEN, raw }, { 0, SECBUFFER_EMPTY, NULL } };
        SecBufferDesc id_ = { SECBUFFER_VERSION, 2, ib };
        SecBuffer ob[2] = { { 0, SECBUFFER_TOKEN, NULL }, { 0, SECBUFFER_ALERT, NULL } };
        SecBufferDesc od = { SECBUFFER_VERSION, 2, ob };
        st = SSP->AcceptSecurityContext(&m->cred, have_ctx ? &ctx : NULL, &id_, MTS_ASC, 0, &ctx, &od, &attr, &ts);
        if (st == SEC_E_INCOMPLETE_MESSAGE) continue;
        if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) have_ctx = 1;
        for (int i = 0; i < 2; i++) if (ob[i].pvBuffer) {
            if (ob[i].cbBuffer && (i == 0 || FAILED(st))) mts_send_all(s, ob[i].pvBuffer, ob[i].cbBuffer);
            SSP->FreeContextBuffer(ob[i].pvBuffer);
        }
        if (ib[1].BufferType == SECBUFFER_EXTRA && ib[1].cbBuffer) { memmove(raw, raw + nraw - ib[1].cbBuffer, ib[1].cbBuffer); nraw = ib[1].cbBuffer; }
        else nraw = 0;
    }
    r->asc = (long)st;
    if (st == SEC_E_OK) {
        r->done = 1;
        SecPkgContext_ConnectionInfo ci; memset(&ci, 0, sizeof ci);
        if (SSP->QueryContextAttributesW(&ctx, SECPKG_ATTR_CONNECTION_INFO, &ci) == SEC_E_OK) r->proto = ci.dwProtocol;
        PCCERT_CONTEXT rc = NULL;
        if (SSP->QueryContextAttributesW(&ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &rc) == SEC_E_OK && rc) { r->client_cert = 1; U(CertFreeCertificateContext)(rc); }
        SecPkgContext_StreamSizes sz; memset(&sz, 0, sizeof sz);
        SSP->QueryContextAttributesW(&ctx, SECPKG_ATTR_STREAM_SIZES, &sz);
        /* read one request head */
        char head[4096]; size_t nh = 0; int got = 0;
        for (int guard = 0; guard < 256 && !got; guard++) {
            if (nraw) {
                SecBuffer b[4] = { { (ULONG)nraw, SECBUFFER_DATA, raw }, { 0, SECBUFFER_EMPTY, NULL }, { 0, SECBUFFER_EMPTY, NULL }, { 0, SECBUFFER_EMPTY, NULL } };
                SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
                SECURITY_STATUS ds = SSP->DecryptMessage(&ctx, &d, 0, NULL);
                if (ds == SEC_E_OK) {
                    size_t extra = 0; char *xp = NULL;
                    for (int i = 0; i < 4; i++) {
                        if (b[i].BufferType == SECBUFFER_DATA && b[i].cbBuffer) {
                            size_t k = b[i].cbBuffer; if (nh + k >= sizeof head) k = sizeof head - 1 - nh;
                            memcpy(head + nh, b[i].pvBuffer, k); nh += k; head[nh] = 0;
                        }
                        if (b[i].BufferType == SECBUFFER_EXTRA && b[i].cbBuffer) { extra = b[i].cbBuffer; xp = raw + nraw - extra; }
                    }
                    if (extra) memmove(raw, xp, extra);
                    nraw = extra;
                    if (strstr(head, "\r\n\r\n")) got = 1;
                    continue;
                }
                if (ds != SEC_E_INCOMPLETE_MESSAGE) break;
            }
            if (nraw >= cap) break;
            int k = SWS.recv(s, raw + nraw, (int)(cap - nraw), 0);
            if (k <= 0) break;
            nraw += k;
        }
        if (got) {
            InterlockedIncrement(&m->nreq); r->nreq = 1;
            char *e = strstr(head, "\r\n"); size_t ll = e ? (size_t)(e - head) : 0; if (ll >= sizeof r->line) ll = sizeof r->line - 1;
            memcpy(r->line, head, ll); r->line[ll] = 0;
            char *u = strstr(head, "\r\nUser-Agent: ");
            if (u) { u += 14; char *ue = strstr(u, "\r\n"); size_t ul = ue ? (size_t)(ue - u) : 0; if (ul >= sizeof r->ua) ul = sizeof r->ua - 1; memcpy(r->ua, u, ul); r->ua[ul] = 0; }
            static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\n" MTS_BODY;
            size_t n = sizeof resp - 1;
            char *buf = malloc(sz.cbHeader + n + sz.cbTrailer + 16);
            memcpy(buf + sz.cbHeader, resp, n);
            SecBuffer b[4] = { { sz.cbHeader, SECBUFFER_STREAM_HEADER, buf }, { (ULONG)n, SECBUFFER_DATA, buf + sz.cbHeader },
                               { sz.cbTrailer, SECBUFFER_STREAM_TRAILER, buf + sz.cbHeader + n }, { 0, SECBUFFER_EMPTY, NULL } };
            SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
            if (SSP->EncryptMessage(&ctx, 0, &d, 0) == SEC_E_OK) mts_send_all(s, buf, b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer);
            free(buf);
            /* close_notify */
            DWORD tok = SCHANNEL_SHUTDOWN; SecBuffer tb = { sizeof tok, SECBUFFER_TOKEN, &tok }; SecBufferDesc td = { SECBUFFER_VERSION, 1, &tb };
            if (SSP->ApplyControlToken && SSP->ApplyControlToken(&ctx, &td) == SEC_E_OK) {
                SecBuffer ob[1] = { { 0, SECBUFFER_TOKEN, NULL } }; SecBufferDesc od = { SECBUFFER_VERSION, 1, ob };
                SECURITY_STATUS cs = SSP->AcceptSecurityContext(&m->cred, &ctx, NULL, MTS_ASC, 0, NULL, &od, &attr, &ts);
                if ((cs == SEC_E_OK || cs == SEC_I_CONTEXT_EXPIRED) && ob[0].pvBuffer && ob[0].cbBuffer) mts_send_all(s, ob[0].pvBuffer, ob[0].cbBuffer);
                if (ob[0].pvBuffer) SSP->FreeContextBuffer(ob[0].pvBuffer);
            }
            SWS.shutdown(s, SD_SEND);
            char tmp[256]; for (int i = 0; i < 20 && SWS.recv(s, tmp, sizeof tmp, 0) > 0; i++) {}
        }
    }
    if (have_ctx) SSP->DeleteSecurityContext(&ctx);
    free(raw);
    SWS.closesocket(s); m->csock[id] = INVALID_SOCKET;
    InterlockedIncrement(&m->nfinished);
    return 0;
}

static DWORD WINAPI mts_accept_thread(LPVOID p) {
    mts *m = p; DWORD t0 = GetTickCount();
    while (GetTickCount() - t0 < 20000 && WaitForSingleObject(m->stop, 0) != WAIT_OBJECT_0) {
        fd_set fs; FD_ZERO(&fs); FD_SET(m->ls, &fs);
        struct timeval tv = { 0, 100000 };
        int r = SWS.select(0, &fs, NULL, NULL, &tv);
        if (r < 0) break;
        if (r == 0) continue;
        SOCKET c = SWS.accept(m->ls, NULL, NULL);
        if (c == INVALID_SOCKET) continue;
        LONG id = m->nconn;
        if (id >= MTS_MAXC) { SWS.closesocket(c); continue; }
        m->csock[id] = c;
        mts_arg *a = malloc(sizeof *a); a->m = m; a->id = id;
        m->cthr[id] = CreateThread(NULL, 0, mts_conn_thread, a, 0, NULL);
        InterlockedIncrement(&m->nconn);
    }
    return 0;
}

mts *mts_start(PCCERT_CONTEXT cert, DWORD protocols) {
    if (!cert || !srv_ws_load() || !srv_sspi_load()) return NULL;
    mts *m = calloc(1, sizeof *m);
    for (int i = 0; i < MTS_MAXC; i++) m->csock[i] = INVALID_SOCKET;
    SCHANNEL_CRED sc; memset(&sc, 0, sizeof sc);
    sc.dwVersion = SCHANNEL_CRED_VERSION; sc.cCreds = 1; sc.paCred = &cert; sc.grbitEnabledProtocols = protocols;
    sc.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER;
    TimeStamp ts;
    SECURITY_STATUS st = SSP->AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_INBOUND, NULL, &sc, NULL, NULL, &m->cred, &ts);
    if (st != SEC_E_OK) { t_note("mts: AcquireCredentialsHandle 0x%lx", st); free(m); return NULL; }
    m->have_cred = 1;
    m->ls = SWS.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = 0x0100007fu;
    int al = sizeof a;
    if (m->ls == INVALID_SOCKET || SWS.bind(m->ls, (struct sockaddr *)&a, sizeof a) || SWS.listen(m->ls, 8) ||
        SWS.getsockname(m->ls, (struct sockaddr *)&a, &al)) {
        if (m->ls != INVALID_SOCKET) SWS.closesocket(m->ls);
        SSP->FreeCredentialsHandle(&m->cred); free(m); return NULL;
    }
    m->port = srv_htons(a.sin_port);
    m->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    m->thr = CreateThread(NULL, 0, mts_accept_thread, m, 0, NULL);
    return m;
}
unsigned short mts_port(mts *m) { return m->port; }
int mts_conns(mts *m) { return (int)m->nconn; }
int mts_requests(mts *m) { return (int)m->nreq; }
int mts_wait_conns(mts *m, int n, DWORD ms) {
    DWORD t0 = GetTickCount();
    while (m->nfinished < n) { if (GetTickCount() - t0 > ms) return 0; Sleep(10); }
    return 1;
}
const mts_conn *mts_get(mts *m, int i) { return (i >= 0 && i < m->nconn) ? &m->rec[i] : NULL; }
void mts_stop(mts *m) {
    if (!m) return;
    SetEvent(m->stop);
    WaitForSingleObject(m->thr, 3000); CloseHandle(m->thr);
    for (int i = 0; i < m->nconn && i < MTS_MAXC; i++) if (m->cthr[i]) {
        if (WaitForSingleObject(m->cthr[i], 6000) != WAIT_OBJECT_0) {
            SOCKET s = m->csock[i]; if (s != INVALID_SOCKET) SWS.closesocket(s);
            WaitForSingleObject(m->cthr[i], 2000);
        }
        CloseHandle(m->cthr[i]);
    }
    SWS.closesocket(m->ls);
    if (m->have_cred) SSP->FreeCredentialsHandle(&m->cred);
    CloseHandle(m->stop);
    free(m);
}

DWORD pki_get(const char *host, unsigned short port, DWORD secflags, DWORD openflags, DWORD *status, treq *keep) {
    treq t; DWORD err;
    if (status) *status = 0;
    if (!treq_open(&t, host ? host : "127.0.0.1", port, "GET", "/p", T_INET_FRESH | INTERNET_FLAG_SECURE | openflags)) {
        err = GetLastError(); treq_close(&t); return err ? err : 1;
    }
    if (secflags) t_https_secflags(t.hr, secflags);
    err = treq_send(&t);
    if (!err && status) *status = treq_status(&t);
    if (keep) *keep = t; else { if (!err) { char b[64]; treq_body(&t, b, sizeof b); } treq_close(&t); }
    return err;
}
