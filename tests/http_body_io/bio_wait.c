/* bio_wait.c - SRV_CALL step that waits for the next request without a blocking recv().
 * WinINet keeps idle keep-alive sockets in its process-wide pool after the handles are closed, and a server
 * connection thread parked in recv() then holds srv_stop() for its whole 3 s grace (shutdown() from another thread
 * does not wake a blocked recv on Windows; measured: 329 tests in 780 s on the Win10 VM). bio_open() inserts this
 * step before every request-reading step, so srv_stop() returns at once. Same technique as
 * tests/http_cache_integration/hci_wait.c. Uses the foundation's private header read-only; no wininet.h here. */
#include "srv_int.h"

int bio_wait_next(srv_conn *c, const srv_step *st, void *user) {
    (void)st; (void)user;
    if (c->nin || (c->tls && c->nraw)) return 0;         /* bytes already buffered */
    for (int i = 0; i < 300; i++) {                      /* <= 30 s, far beyond any idle gap in this area */
        if (c->s->stop || c->sock == INVALID_SOCKET) return -1;
        fd_set rs; FD_ZERO(&rs); FD_SET(c->sock, &rs);
        struct timeval tv = { 0, 50000 };
        int r = SWS.select(0, &rs, NULL, NULL, &tv);
        if (r > 0) return 0;                             /* data or EOF: let the real step read it */
        if (r < 0) return -1;
    }
    return -1;
}
