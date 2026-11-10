/* srv_tls.c - self-signed certificate profiles and the schannel server side (AcceptSecurityContext loop,
 * Encrypt/DecryptMessage, close_notify). Design + Win10 measurements: docs/research/04 section 1.3, F7-F11. */
#include "srv_int.h"
#include "modules.h"

/* ------------------------------------------------------------------ certificates */
typedef struct { PCCERT_CONTEXT cert; WCHAR container[96]; int cng, made; } cert_slot;
static cert_slot g_certs[SRV_CERT_COUNT];
static INIT_ONCE g_cert_once = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_cert_cs;
static BOOL CALLBACK cert_once(PINIT_ONCE o, PVOID p, PVOID *ctx) { InitializeCriticalSection(&g_cert_cs); return TRUE; }

static void delete_key(cert_slot *k) {
    if (k->cng) {
        NCRYPT_PROV_HANDLE np; NCRYPT_KEY_HANDLE nk;
        if (SNC.ok && !SNC.NCryptOpenStorageProvider(&np, MS_KEY_STORAGE_PROVIDER, 0)) {
            if (!SNC.NCryptOpenKey(np, &nk, k->container, 0, 0)) SNC.NCryptDeleteKey(nk, 0);
            SNC.NCryptFreeObject(np);
        }
    } else { HCRYPTPROV hp; CryptAcquireContextW(&hp, k->container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET); }
}
static void cert_cleanup(void) {
    for (int i = 0; i < SRV_CERT_COUNT; i++) {
        cert_slot *k = &g_certs[i];
        if (!k->made) continue;
        if (k->cert) SCR.CertFreeCertificateContext(k->cert);
        k->cert = NULL;
        delete_key(k); k->made = 0;
    }
}
static void st_add_days(SYSTEMTIME *st, int days) {
    FILETIME ft; ULARGE_INTEGER u; SystemTimeToFileTime(st, &ft);
    u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    u.QuadPart += (LONGLONG)days * 86400LL * 10000000LL;
    ft.dwLowDateTime = u.LowPart; ft.dwHighDateTime = u.HighPart; FileTimeToSystemTime(&ft, st);
}

static PCCERT_CONTEXT make_cert(int profile, cert_slot *k, int allow_cng) {
    const WCHAR *cn = profile == SRV_CERT_CN_OTHER ? L"CN=i7-other.invalid" : profile == SRV_CERT_CLIENT ? L"CN=i7-client" : L"CN=localhost";
    swprintf(k->container, 96, L"%hs_%lu_%d", T_TMP_PREFIX, GetCurrentProcessId(), profile);
    BYTE name[256]; DWORD nl = sizeof name;
    if (!SCR.CertStrToNameW(X509_ASN_ENCODING, cn, CERT_X500_NAME_STR, NULL, name, &nl, NULL)) return NULL;
    CERT_NAME_BLOB nb = { nl, name };
    CRYPT_KEY_PROV_INFO kpi; memset(&kpi, 0, sizeof kpi); kpi.pwszContainerName = k->container;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hk = 0; HCRYPTPROV hp = 0; NCRYPT_PROV_HANDLE np = 0; NCRYPT_KEY_HANDLE nk = 0;
    SECURITY_STATUS ss = 1;
    if (SNC.ok && allow_cng) {   /* CNG first (0.6 ms vs 18 ms on Win10, F7) */
        ss = SNC.NCryptOpenStorageProvider(&np, MS_KEY_STORAGE_PROVIDER, 0);
        if (!ss) ss = SNC.NCryptCreatePersistedKey(np, &nk, BCRYPT_RSA_ALGORITHM, k->container, 0, NCRYPT_OVERWRITE_KEY_FLAG);
        DWORD bits = 2048; if (!ss) ss = SNC.NCryptSetProperty(nk, NCRYPT_LENGTH_PROPERTY, (BYTE *)&bits, sizeof bits, 0);
        if (!ss) ss = SNC.NCryptFinalizeKey(nk, 0);
        if (!ss) { k->cng = 1; hk = nk; kpi.pwszProvName = MS_KEY_STORAGE_PROVIDER; }
        else { if (nk) SNC.NCryptFreeObject(nk); nk = 0; }
    }
    if (ss) {       /* CAPI fallback */
        if (!CryptAcquireContextW(&hp, k->container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET) &&
            !CryptAcquireContextW(&hp, k->container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, 0)) { if (np) SNC.NCryptFreeObject(np); return NULL; }
        HCRYPTKEY key;
        if (!CryptGenKey(hp, AT_KEYEXCHANGE, (2048 << 16) | CRYPT_EXPORTABLE, &key)) { CryptReleaseContext(hp, 0); if (np) SNC.NCryptFreeObject(np); return NULL; }
        CryptDestroyKey(key);
        k->cng = 0; hk = hp; kpi.pwszProvName = MS_ENH_RSA_AES_PROV_W; kpi.dwProvType = PROV_RSA_AES; kpi.dwKeySpec = AT_KEYEXCHANGE;
    }
    k->made = 1;
    CERT_EXTENSION ext[2]; int next = 0; BYTE sanbuf[256], ekubuf[64]; DWORD sanl = sizeof sanbuf, ekul = sizeof ekubuf;
    if (profile == SRV_CERT_LOCALHOST || profile == SRV_CERT_EXPIRED || profile == SRV_CERT_NO_EKU) {
        CERT_ALT_NAME_ENTRY e[3]; BYTE ip4[4] = { 127, 0, 0, 1 }, ip6[16] = { 0 }; ip6[15] = 1;
        e[0].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME; e[0].pwszDNSName = L"localhost";
        e[1].dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS; e[1].IPAddress.cbData = 4; e[1].IPAddress.pbData = ip4;
        e[2].dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS; e[2].IPAddress.cbData = 16; e[2].IPAddress.pbData = ip6;
        CERT_ALT_NAME_INFO an = { 3, e };
        if (SCR.CryptEncodeObject(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &an, sanbuf, &sanl)) {
            ext[next].pszObjId = szOID_SUBJECT_ALT_NAME2; ext[next].fCritical = FALSE; ext[next].Value.cbData = sanl; ext[next].Value.pbData = sanbuf; next++;
        }
    }
    if (profile != SRV_CERT_NO_EKU) {
        LPSTR eku[1] = { profile == SRV_CERT_CLIENT ? szOID_PKIX_KP_CLIENT_AUTH : szOID_PKIX_KP_SERVER_AUTH };
        CERT_ENHKEY_USAGE u = { 1, eku };
        if (SCR.CryptEncodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &u, ekubuf, &ekul)) {
            ext[next].pszObjId = szOID_ENHANCED_KEY_USAGE; ext[next].fCritical = FALSE; ext[next].Value.cbData = ekul; ext[next].Value.pbData = ekubuf; next++;
        }
    }
    CERT_EXTENSIONS exts = { (DWORD)next, ext };
    CRYPT_ALGORITHM_IDENTIFIER alg; memset(&alg, 0, sizeof alg); alg.pszObjId = szOID_RSA_SHA256RSA;
    SYSTEMTIME st0, st1; GetSystemTime(&st0); st1 = st0;   /* guest time (04 F14) */
    if (profile == SRV_CERT_EXPIRED) { st_add_days(&st0, -30); st_add_days(&st1, -1); }
    else { st_add_days(&st0, -1); st_add_days(&st1, 365); }
    PCCERT_CONTEXT c = SCR.CertCreateSelfSignCertificate(hk, &nb, 0, &kpi, &alg, &st0, &st1, next ? &exts : NULL);
    if (nk) SNC.NCryptFreeObject(nk);
    if (np) SNC.NCryptFreeObject(np);
    if (hp) CryptReleaseContext(hp, 0);
    return c;
}

PCCERT_CONTEXT srv_cert_get(int profile) {
    if (profile < 0 || profile >= SRV_CERT_COUNT) return NULL;
    if (!srv_crypt_load()) return NULL;
    InitOnceExecuteOnce(&g_cert_once, cert_once, NULL, NULL);
    EnterCriticalSection(&g_cert_cs);
    static int registered;
    cert_slot *k = &g_certs[profile];
    if (!k->cert) {
        if (!registered) { atexit(cert_cleanup); registered = 1; }
        k->cert = make_cert(profile, k, 1);
        if (!k->cert && k->made) { delete_key(k); k->made = 0; }
        if (!k->cert) {   /* e.g. a CNG key the signer cannot use (Wine): retry with a CAPI key */
            k->cert = make_cert(profile, k, 0);
            if (!k->cert && k->made) { delete_key(k); k->made = 0; }
        }
    }
    PCCERT_CONTEXT c = k->cert;
    LeaveCriticalSection(&g_cert_cs);
    return c;
}

/* ------------------------------------------------------------------ credentials */
int srv_tls_cred(srv *s) {
    if (!srv_sspi_load() || !srv_crypt_load()) return SRV_E_UNAVAILABLE;
    PCCERT_CONTEXT cert = srv_cert_get(s->cfg.cert_profile);
    if (!cert) return SRV_E_CERT;
    SECURITY_STATUS st = SEC_E_UNKNOWN_CREDENTIALS; TimeStamp ts;
    DWORD flags = s->cfg.tls_client_cert ? SCH_CRED_NO_SYSTEM_MAPPER : 0;
    if (s->cfg.tls_protocols) {
        TLS_PARAMETERS tp; memset(&tp, 0, sizeof tp);
        DWORD all = SP_PROT_SSL3_SERVER | SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
        tp.grbitDisabledProtocols = all & ~s->cfg.tls_protocols;
        SCH_CREDENTIALS sc; memset(&sc, 0, sizeof sc);
        sc.dwVersion = SCH_CREDENTIALS_VERSION; sc.cCreds = 1; sc.paCred = &cert; sc.dwFlags = flags;
        sc.cTlsParameters = 1; sc.pTlsParameters = &tp;
        st = SSP->AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_INBOUND, NULL, &sc, NULL, NULL, &s->cred, &ts);
    }
    if (st != SEC_E_OK) {   /* SCHANNEL_CRED v4: default, or fallback for systems without SCH_CREDENTIALS */
        SCHANNEL_CRED sc; memset(&sc, 0, sizeof sc);
        sc.dwVersion = SCHANNEL_CRED_VERSION; sc.cCreds = 1; sc.paCred = &cert; sc.dwFlags = flags;
        sc.grbitEnabledProtocols = s->cfg.tls_protocols;
        st = SSP->AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_INBOUND, NULL, &sc, NULL, NULL, &s->cred, &ts);
    }
    if (st != SEC_E_OK) { t_note("srv: schannel inbound credential failed 0x%lx", st); return SRV_E_UNAVAILABLE; }
    s->have_cred = 1;
    return SRV_OK;
}
void srv_tls_cred_free(srv *s) { if (s->have_cred) { SSP->FreeCredentialsHandle(&s->cred); s->have_cred = 0; } }

/* ------------------------------------------------------------------ handshake + record layer */
static void raw_reserve(srv_conn *c, size_t more) {
    if (c->nraw + more > c->capraw) {
        size_t cap = c->capraw ? c->capraw : 32768;
        while (cap < c->nraw + more) cap *= 2;
        c->raw = realloc(c->raw, cap); c->capraw = cap;
    }
}
static int raw_more(srv_conn *c) {
    raw_reserve(c, 16384);
    int r = srv_raw_recv(c, c->raw + c->nraw, 16384);
    if (r > 0) c->nraw += r;
    return r;
}
static int send_all(srv_conn *c, const void *p, size_t n) {
    const char *b = p;
    while (n) { int k = SWS.send(c->sock, b, (int)n, 0); if (k <= 0) return -1; b += k; n -= k; }
    return 0;
}

#define ASC_FLAGS (ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM)

int srv_tls_accept(srv_conn *c) {
    srv *s = c->s; SECURITY_STATUS st = SEC_I_CONTINUE_NEEDED; ULONG attr; TimeStamp ts;
    ULONG req = ASC_FLAGS | (s->cfg.tls_client_cert ? ASC_REQ_MUTUAL_AUTH : 0);
    for (int rounds = 0; st == SEC_I_CONTINUE_NEEDED || st == SEC_E_INCOMPLETE_MESSAGE; rounds++) {
        if (rounds > 24) { srv_recordf(s, SRV_EV_TLS_ABORT, c->id, "too many rounds"); return -1; }
        if (c->nraw == 0 || st == SEC_E_INCOMPLETE_MESSAGE) {
            int r = raw_more(c);
            if (r <= 0) { srv_recordf(s, SRV_EV_TLS_ABORT, c->id, "handshake recv=%d round=%d", r, rounds); return -1; }
        }
        SecBuffer ib[2] = { { (ULONG)c->nraw, SECBUFFER_TOKEN, c->raw }, { 0, SECBUFFER_EMPTY, NULL } };
        SecBufferDesc id = { SECBUFFER_VERSION, 2, ib };
        SecBuffer ob[2] = { { 0, SECBUFFER_TOKEN, NULL }, { 0, SECBUFFER_ALERT, NULL } };
        SecBufferDesc od = { SECBUFFER_VERSION, 2, ob };
        st = SSP->AcceptSecurityContext(&s->cred, c->have_ctx ? &c->ctx : NULL, &id, req, 0, &c->ctx, &od, &attr, &ts);
        if (st == SEC_E_INCOMPLETE_MESSAGE) continue;
        if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) c->have_ctx = 1;
        for (int i = 0; i < 2; i++) if (ob[i].pvBuffer) {
            if (ob[i].cbBuffer && (i == 0 || FAILED(st))) send_all(c, ob[i].pvBuffer, ob[i].cbBuffer);
            SSP->FreeContextBuffer(ob[i].pvBuffer);
        }
        if (ib[1].BufferType == SECBUFFER_EXTRA && ib[1].cbBuffer) { memmove(c->raw, c->raw + c->nraw - ib[1].cbBuffer, ib[1].cbBuffer); c->nraw = ib[1].cbBuffer; }
        else c->nraw = 0;
        if (FAILED(st)) { srv_recordf(s, SRV_EV_TLS_ABORT, c->id, "ASC=0x%lx round=%d", st, rounds); return -1; }
    }
    if (st != SEC_E_OK) { srv_recordf(s, SRV_EV_TLS_ABORT, c->id, "handshake end 0x%lx", st); return -1; }
    SSP->QueryContextAttributesW(&c->ctx, SECPKG_ATTR_STREAM_SIZES, &c->sz);
    SecPkgContext_ConnectionInfo ci; memset(&ci, 0, sizeof ci);
    SSP->QueryContextAttributesW(&c->ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
    SecPkgContext_CipherInfo cip; memset(&cip, 0, sizeof cip); cip.dwVersion = SECPKGCONTEXT_CIPHERINFO_V1;
    SSP->QueryContextAttributesW(&c->ctx, SECPKG_ATTR_CIPHER_INFO, &cip);
    PCCERT_CONTEXT rc = NULL;
    int have_cc = SSP->QueryContextAttributesW(&c->ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &rc) == SEC_E_OK && rc;
    if (rc) SCR.CertFreeCertificateContext(rc);
    srv_recordf(s, SRV_EV_TLS_DONE, c->id, "proto=0x%lx cipher=0x%x suite=0x%lx client_cert=%d", ci.dwProtocol, ci.aiCipher, cip.dwCipherSuite, have_cc);
    if (s->cfg.tls_client_cert == 2 && !have_cc) { srv_recordf(s, SRV_EV_TLS_ABORT, c->id, "client certificate required"); return -1; }
    return 0;
}

int srv_tls_fill(srv_conn *c) {
    srv *s = c->s;
    for (int guard = 0; guard < 4096; guard++) {
        if (c->nraw) {
            SecBuffer b[4] = { { (ULONG)c->nraw, SECBUFFER_DATA, c->raw }, { 0, SECBUFFER_EMPTY, NULL }, { 0, SECBUFFER_EMPTY, NULL }, { 0, SECBUFFER_EMPTY, NULL } };
            SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
            SECURITY_STATUS st = SSP->DecryptMessage(&c->ctx, &d, 0, NULL);
            if (st == SEC_E_OK || st == SEC_I_CONTEXT_EXPIRED || st == SEC_I_RENEGOTIATE) {
                size_t added = 0, extra = 0; char *xp = NULL;
                for (int i = 0; i < 4; i++) {
                    if (b[i].BufferType == SECBUFFER_DATA && b[i].cbBuffer) {
                        srv_io_reserve(c, b[i].cbBuffer); memcpy(c->in + c->nin, b[i].pvBuffer, b[i].cbBuffer);
                        c->nin += b[i].cbBuffer; c->in[c->nin] = 0; added += b[i].cbBuffer;
                    }
                    if (b[i].BufferType == SECBUFFER_EXTRA && b[i].cbBuffer) { extra = b[i].cbBuffer; xp = c->raw + c->nraw - extra; }
                }
                if (extra) memmove(c->raw, xp, extra);
                c->nraw = extra;
                if (st == SEC_I_CONTEXT_EXPIRED) { srv_recordf(s, SRV_EV_EOF, c->id, "close_notify"); return added ? (int)added : 0; }
                if (st == SEC_I_RENEGOTIATE) { srv_recordf(s, SRV_EV_ERROR, c->id, "peer requested renegotiation (unsupported)"); return added ? (int)added : -1; }
                if (added) return (int)added;
                continue;
            }
            if (st != SEC_E_INCOMPLETE_MESSAGE) { srv_recordf(s, SRV_EV_ERROR, c->id, "DecryptMessage 0x%lx", st); return -1; }
        }
        int r = raw_more(c);
        if (r == 0) { srv_record(s, SRV_EV_EOF, c->id, -1, NULL, 0); return 0; }
        if (r < 0) return -1;
    }
    return -1;
}

int srv_tls_send(srv_conn *c, const void *p, size_t n) {
    const char *src = p; size_t maxm = c->sz.cbMaximumMessage ? c->sz.cbMaximumMessage : 16384;
    char *buf = malloc(c->sz.cbHeader + maxm + c->sz.cbTrailer);
    int rc = 0;
    while (n && !rc) {
        size_t k = n < maxm ? n : maxm;
        memcpy(buf + c->sz.cbHeader, src, k);
        SecBuffer b[4] = { { c->sz.cbHeader, SECBUFFER_STREAM_HEADER, buf }, { (ULONG)k, SECBUFFER_DATA, buf + c->sz.cbHeader },
                           { c->sz.cbTrailer, SECBUFFER_STREAM_TRAILER, buf + c->sz.cbHeader + k }, { 0, SECBUFFER_EMPTY, NULL } };
        SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
        SECURITY_STATUS st = SSP->EncryptMessage(&c->ctx, 0, &d, 0);
        if (st != SEC_E_OK) { srv_recordf(c->s, SRV_EV_ERROR, c->id, "EncryptMessage 0x%lx", st); rc = -1; break; }
        if (send_all(c, buf, b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer)) { srv_recordf(c->s, SRV_EV_ERROR, c->id, "tls send failed"); rc = -1; }
        src += k; n -= k;
    }
    free(buf); return rc;
}

void srv_tls_shutdown(srv_conn *c) {
    if (!c->have_ctx || c->closed_notify || c->sock == INVALID_SOCKET) return;
    c->closed_notify = 1;
    DWORD tok = SCHANNEL_SHUTDOWN; SecBuffer tb = { sizeof tok, SECBUFFER_TOKEN, &tok }; SecBufferDesc td = { SECBUFFER_VERSION, 1, &tb };
    if (!SSP->ApplyControlToken || SSP->ApplyControlToken(&c->ctx, &td) != SEC_E_OK) return;
    SecBuffer ob[1] = { { 0, SECBUFFER_TOKEN, NULL } }; SecBufferDesc od = { SECBUFFER_VERSION, 1, ob }; ULONG attr; TimeStamp ts;
    SECURITY_STATUS st = SSP->AcceptSecurityContext(&c->s->cred, &c->ctx, NULL, ASC_FLAGS, 0, NULL, &od, &attr, &ts);
    if ((st == SEC_E_OK || st == SEC_I_CONTEXT_EXPIRED) && ob[0].pvBuffer && ob[0].cbBuffer) send_all(c, ob[0].pvBuffer, ob[0].cbBuffer);
    if (ob[0].pvBuffer) SSP->FreeContextBuffer(ob[0].pvBuffer);
}
void srv_tls_free(srv_conn *c) { if (c->have_ctx) { SSP->DeleteSecurityContext(&c->ctx); c->have_ctx = 0; } }
