# net_loopback evidence

## triage 2026-11-11

- netlb_https_tls12_only_server: cause = test/harness timing (flake). The first TLS use in the
  process failed intermittently (2 of 3 VM runs) with err=12030 ERROR_INTERNET_CONNECTION_ABORTED.
  Added diagnostics showed the server events ACCEPT, TIMEOUT "recv timeout", TLS_ABORT: the
  client had not sent its ClientHello within the server's default 5 s io_timeout_ms (cold
  schannel/wininet init in a fresh VM). The same server config passes in https_tls
  (tls_proto_server_tls12_only) when it is not the first TLS use. Change: cfg.io_timeout_ms = 30000
  for this test, plus t_note diagnostics of the server events. The CHECKs themselves are unchanged.
