# Public RFC 3161 interoperability fixture

Fetched on 2026-08-26 at 16:32 UTC over the digest recorded in `provenance.json`. FreeTSA
(`https://freetsa.org/tsr`) and Sectigo (`https://timestamp.sectigo.com`) are independent public
authorities not operated by Mizan. Both responses verify offline in one bundle.

The roots beside this README exist only to make this regression fixture reproducible. They are not
inside `bundle/`. A real verifier obtains trust roots from its operator and must never trust roots
supplied by the evidence bundle (B-12).

Incompatibilities and failed attempts:

- `https://timestamp.digicert.com` was unreachable from this host (TCP connection failure after
  8.274 seconds) and was not substituted or counted.
- Both successful authorities required an RFC 3161 request with SHA-256 and accepted `-cert`,
  `Content-Type: application/timestamp-query`, and `Accept: application/timestamp-reply`.
- FreeTSA included its self-signed root in the response; verification still used the separately
  fetched root at `https://freetsa.org/files/cacert.pem`.
- Sectigo returned its signer and intermediate/cross-certificate chain. OpenSSL constructed the
  chain to the separately selected USERTrust RSA root without an extra `-untrusted` file.
- Neither successful authority required a nonce beyond OpenSSL's default query shape. No policy OID
  override or hash-algorithm fallback was required.

`verification-result.txt` is the committed stdout of the standalone offline verification command.
