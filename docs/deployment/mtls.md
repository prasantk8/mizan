# In-process mTLS deployment contract

Mizan v1 terminates workload mTLS in the application process. The listener must use TLS 1.2 or
newer, load the deployment server certificate/private key, load the approved client CA trust bundle,
and set `CERT_REQUIRED`. A handshake with no client certificate or an untrusted chain must fail
before ASGI dispatch.

The ASGI server adapter must expose the verified connection's Python `SSLObject` as
`scope["ssl_object"]`. `VerifiedPeerSpiffeMiddleware` checks that its SSL context used
`CERT_REQUIRED`, parses the peer X.509 certificate, and accepts exactly one URI SAN beginning
`spiffe://`. It then populates `scope["client_cert_spiffe"]` for execution endpoints. Missing
certificates, missing URI SANs, multiple SPIFFE URI SANs, malformed certificates, and optional client
verification all remain unauthenticated and receive 401.

Do not forward workload identity in HTTP headers. Mizan v1 has no trusted-proxy-header mode, and it
never derives workload identity from certificate CN or subject DN. A future proxy-terminated mode
requires a separate ADR-001 threat analysis and authenticated hop contract.

Certificate issuance and rotation are external to Mizan (SPIFFE/SPIRE or the deployment PKI). The
trust bundle must contain only workload-issuing authorities approved for the deployment; changing it
is an infrastructure security operation. A readiness probe must exercise a real mutually
authenticated connection and verify the expected SPIFFE URI reaches an execution route.

The readiness document is available at both `/health/ready` and `/readyz`; they are aliases backed
by the same handler and return the same status and checks. The production image and supported
Compose path use `/readyz`. A 200 response means the database, signing keys, evidence verifier,
execution service, RFC 3161 configuration, and mutual-TLS configuration are all usable; a partial
configuration returns 503 rather than reporting the process ready.
