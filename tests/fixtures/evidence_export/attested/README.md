# Attested offline-verifier fixture

This bundle carries a real RFC 3161 response created on 2026-08-26 by the repository's
OpenSSL-based local test TSA. `tsa-root.pem` is the operator-supplied trust root for this fixture;
it is deliberately outside `bundle/`, because evidence bundles never supply their own trust root.

The fixture is CI-only regression evidence for the standalone verifier's attested path. It does
not claim public-TSA interoperability or production custody.
