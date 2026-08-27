# Attested offline-verifier fixture

This bundle carries a real RFC 3161 response created on 2026-08-26 by the repository's
OpenSSL-based local test TSA. `tsa-root.pem` is the operator-supplied trust root for this fixture;
it is deliberately outside `bundle/`, because evidence bundles never supply their own trust root.

The fixture is CI-only regression evidence for the standalone verifier's attested path. It does
not claim public-TSA interoperability or production custody.

`tsa-root.pem` has a ten-year lifetime, which is what a competently operated authority looks like
and is why this fixture stays `VALID`. Its predecessor had a twenty-four-hour lifetime and was
R-008 F-10. The horizon that matters is tested by `../expired/`, which can never be un-expired —
read its README before touching either. Regenerate both with `scripts/build_tsa_fixtures.py`.
