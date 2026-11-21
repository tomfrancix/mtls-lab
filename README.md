# Real mTLS Laboratory

A **real, loopback TCP/TLS/HTTP** demonstration using Python's `ssl` module and OpenSSL-issued X.509 certificates. No mocked handshakes. Both peers run as independent sockets, with the server in a background thread; the client and server each have their own SSL context and trust store.

## Requirements

- Python 3.11 or newer (standard library only)
- OpenSSL CLI on `PATH` (OpenSSL 3 recommended)
- VS Code with Microsoft's Python extension for F5 debugging
- macOS, Linux, or Windows (on Windows, install OpenSSL separately or use WSL)

## Quick start

```bash
python main.py setup
python main.py list
python main.py run success
python main.py run missing-client-cert
python main.py all
```

On some systems use `python3` or `py -3` instead of `python`.

Open this folder in VS Code, select the Python interpreter, then open **Run and Debug** and choose **mTLS: all failure modes**. The VS Code launch configurations are in `.vscode/launch.json`. Generate certificates once before launching.

## Architecture

```text
                   LOCAL TRUSTED CA
                    /           \
              server.crt       client.crt
                   |               |
          TLS server socket   TLS client socket
              127.0.0.1       ephemeral source port
                   |               |
                   +--- TLS 1.2/1.3 handshake ---+
                   +--- HTTP/1.0 GET /hello -----+

Client validates: server certificate chain, time, serverAuth EKU, SAN hostname.
Server validates: client certificate chain, time, clientAuth EKU.
```

The server binds to loopback on an OS-selected ephemeral port, avoiding external network access and port conflicts. The client connects using `localhost` as the TLS hostname. The certificate SAN is `DNS:localhost`. All generated private keys are **test-only**, unencrypted, and written to `.generated/pki`, which is excluded from Git.

## Source modules

- `lab/certificates.py`: OpenSSL PKI issuance; separate trusted and rogue CAs, positive and negative certificates.
- `lab/transport.py`: socket creation, SSL contexts, actual handshake, HTTP request/response, and endpoint errors.
- `lab/scenarios.py`: immutable, isolated configuration changes for each failure.
- `main.py`: setup, list, inspect, run, all commands.

## Failure matrix

| Scenario | What is broken | Expected |
|---|---|---|
| `success` | Nothing | HTTP 200 |
| `missing-client-cert` | Client presents no certificate | Server rejects |
| `untrusted-client` | Client certificate signed by rogue CA | Server rejects |
| `expired-client` | Client certificate expired in 2020 | Server rejects |
| `wrong-client-eku` | Client certificate has only `serverAuth` EKU | Server rejects |
| `untrusted-server` | Server certificate signed by rogue CA | Client rejects |
| `hostname-mismatch` | Server SAN does not match `localhost` | Client rejects |
| `wrong-server-eku` | Server certificate has only `clientAuth` EKU | Client rejects |
| `wrong-client-trust-store` | Client trusts wrong CA | Client rejects |
| `wrong-server-trust-store` | Server trusts wrong CA | Server rejects |
| `tls-version-mismatch` | Server requires TLS 1.3, client supports at most 1.2 | Handshake fails |
| `client-auth-disabled` | Server disables client certificate requirement | HTTP 200 (insecure control) |
| `server-verification-disabled` | Client disables server validation | HTTP 200 (insecure control) |

**Important:** The side which detects an invalid certificate generally emits the meaningful certificate validation error. The other side may see only `TLSV1_ALERT_UNKNOWN_CA`, `SSLV3_ALERT_BAD_CERTIFICATE`, `TLSV1_ALERT_CERTIFICATE_EXPIRED`, `EOF`, or another alert. Exact OpenSSL/Python error wording varies by platform and TLS version. A TLS client can sometimes finish its local handshake before observing a server-side rejection; therefore the laboratory checks for an actual successful HTTP exchange, not merely whether `wrap_socket` returned.

## Certificate inspection

```bash
python main.py inspect server
python main.py inspect expired-client
openssl verify -CAfile .generated/pki/trusted-ca.crt -purpose sslclient .generated/pki/client.crt
openssl verify -CAfile .generated/pki/trusted-ca.crt -purpose sslclient .generated/pki/wrong-eku-client.crt
openssl verify -CAfile .generated/pki/trusted-ca.crt -purpose sslclient .generated/pki/expired-client.crt
openssl x509 -in .generated/pki/server.crt -noout -dates -ext subjectAltName -ext extendedKeyUsage
```

## Debugging exercises

1. Set a breakpoint at `context.wrap_socket` in `lab/transport.py`. Observe which peer raises and compare the client and server exceptions.
2. Set a breakpoint at `tls.getpeercert()` and inspect authenticated identities.
3. Run `python main.py inspect client` and compare its EKU to `wrong-eku-client`.
4. Run `untrusted-client`, then inspect both the rogue CA's issuer relationship and the server's `load_verify_locations` call.
5. Compare `missing-client-cert` with `client-auth-disabled`. TLS encryption without client authentication is **not** mTLS.
6. Compare `untrusted-server` with `server-verification-disabled`. A successful connection with certificate verification disabled does **not** establish server identity.

## What this laboratory deliberately does not claim to cover

Certificate revocation (CRL/OCSP), intermediate CA path-building, name constraints, Kubernetes secret rotation, SNI-based certificate selection, TLS session resumption, and production identity mapping are separate concerns. Revocation checks in particular are **not enabled by default** in many TLS stacks; this lab does not pretend an issued-but-revoked certificate will automatically be rejected. These would be worthwhile follow-on modules.

## Security

Do not use the generated certificates outside this laboratory. Do not copy the test CA into an OS trust store. Do not deploy `client-auth-disabled` or `server-verification-disabled` to production. Regenerate with `python main.py setup` if you want a fresh PKI. `setup` replaces the named generated certificates and OpenSSL CA bookkeeping.
