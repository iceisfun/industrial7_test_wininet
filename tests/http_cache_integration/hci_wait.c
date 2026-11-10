/* hci_wait.c - lets the area's SRV_CALL responders wait for the next request without a blocking recv().
 * WinINet keeps idle keep-alive sockets in its process-wide pool after the session handle is closed, so a responder
 * parked in recv() holds srv_stop() for its full 3 s grace (a shutdown() from another thread does not wake a blocked
 * recv() on Windows). Polling select() and the server's stop flag ends the responder at once.
 * Uses the foundation's private header (read-only); no wininet.h here. */
#include "srv_int.h"

int hci_wait_request(srv_conn *c) {
    if (c->nin || (c->tls && c->nraw)) return 1;        /* bytes already buffered */
    for (int i = 0; i < 300; i++) {                     /* <= 30 s, far beyond any test's idle gap */
        if (c->s->stop || c->sock == INVALID_SOCKET) return 0;
        fd_set rs; FD_ZERO(&rs); FD_SET(c->sock, &rs);
        struct timeval tv = { 0, 100000 };
        int r = SWS.select(0, &rs, NULL, NULL, &tv);
        if (r > 0) return 1;
        if (r < 0) return 0;
    }
    return 0;
}
