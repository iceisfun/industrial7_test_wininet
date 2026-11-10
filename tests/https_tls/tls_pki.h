/* tls_pki.h - a small certificate factory and a minimal schannel HTTPS server for the https_tls area.
 *
 * The shared server (common/srv_tls.c) only serves its five self-signed profiles. These helpers build real chains
 * (a per-process test root CA, leaves it signs, optional CRL distribution point / AIA URLs, CRLs) and serve them from a
 * small TLS server that answers every request with a fixed 200 response. Nothing is added to any certificate store:
 * the root is never trusted, so every test reaches the success path with SECURITY_FLAG_IGNORE_UNKNOWN_CA (0x100) or
 * observes the error that remains once it is set. Keys are CAPI keys in containers named wininet_<pid>_pki<n>,
 * deleted at exit. All servers bind 127.0.0.1 only, live at most 20 s and are joined by mts_stop.
 */
#ifndef TLS_PKI_H
#define TLS_PKI_H
#include "tls_util.h"

/* EKU choices */
enum { PKI_EKU_NONE = 0, PKI_EKU_SERVER, PKI_EKU_CLIENT, PKI_EKU_BOTH, PKI_EKU_ANY, PKI_EKU_CODESIGN };
/* signature hash */
enum { PKI_SHA256 = 0, PKI_SHA1, PKI_MD5, PKI_SHA384 };

typedef struct {
    const char *subject;    /* X.500 string, e.g. "CN=localhost" */
    int nb_days, na_days;   /* NotBefore / NotAfter relative to now (guest clock), in days */
    const char *san;        /* comma list "dns:localhost,ip4:127.0.0.1,ip6:::1" or NULL (no SAN extension) */
    int eku;                /* PKI_EKU_* */
    int ca;                 /* 1: basicConstraints CA:TRUE (critical) + keyCertSign|cRLSign key usage */
    const char *cdp;        /* CRL distribution point URL, or NULL */
    const char *aia;        /* AIA caIssuers URL, or NULL */
    int hash;               /* PKI_SHA* */
    int bits;               /* RSA modulus bits (0 = 2048) */
    BYTE ku;                /* key usage first byte for a leaf (0 = no extension), e.g. 0xA0 digitalSignature|keyEncipherment */
} pki_spec;

typedef struct pki_ent {
    PCCERT_CONTEXT cert;    /* standalone context (no store) */
    HCRYPTPROV prov;        /* private key (AT_KEYEXCHANGE) */
    WCHAR container[64];
    BYTE serial[8];
} pki_ent;

/* issuer NULL: self-signed. Returns NULL on failure (caller t_skip). Freed at exit. */
pki_ent *pki_make(const pki_spec *sp, pki_ent *issuer);
/* The per-process test root ("CN=i7 Test Root <pid>"), created once. */
pki_ent *pki_root(void);
/* DER CRL signed by ca listing the given entries as revoked (malloc'd, free()). next_days: nextUpdate offset. */
BYTE *pki_crl(pki_ent *ca, pki_ent **revoked, int nrev, int next_days, DWORD *len);
/* Server credential store: the leaf (with its key) plus the extra certs the server may send in its chain.
 * Returns the leaf context inside a memory store (CertFreeCertificateContext + the store go at exit). */
PCCERT_CONTEXT pki_server_cert(pki_ent *leaf, pki_ent **chain, int nchain);
/* "CN=..." -> CertNameToStrA(SIMPLE) of the subject / issuer, for comparisons. */
const char *pki_simple_name(PCCERT_CONTEXT c, int issuer);

/* ------------------------------------------------------------------ minimal schannel HTTPS server */
typedef struct mts mts;
#define MTS_MAXC 16
typedef struct {
    int done;                 /* handshake finished */
    long asc;                 /* last AcceptSecurityContext status (0 ok) */
    int nreq;                 /* request heads decrypted on this connection */
    char line[256];           /* first request line */
    char ua[160];             /* User-Agent of the first request */
    DWORD proto;              /* SecPkgContext_ConnectionInfo.dwProtocol */
    int client_cert;          /* client presented a certificate */
} mts_conn;
/* protocols: SP_PROT_*_SERVER bits to enable (0 = default). Response body "pki-ok". */
mts *mts_start(PCCERT_CONTEXT cert, DWORD protocols);
unsigned short mts_port(mts *m);
int  mts_conns(mts *m);                 /* connections accepted */
int  mts_wait_conns(mts *m, int n, DWORD ms); /* wait for n finished connections */
const mts_conn *mts_get(mts *m, int i);
int  mts_requests(mts *m);              /* total request heads */
void mts_stop(mts *m);
#define MTS_BODY "pki-ok"

/* One GET /p on a fresh session to host:port with secflags ORed in before the send. Returns 0 or the error,
 * *status = HTTP status, body copied (NUL-terminated) if buf. Leaves the request open in *t when keep != 0. */
DWORD pki_get(const char *host, unsigned short port, DWORD secflags, DWORD openflags, DWORD *status, treq *keep);
#endif
