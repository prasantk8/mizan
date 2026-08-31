"""Public-only test material shared by startup tests that never authenticate a request."""

UNUSED_IDENTITY_JWKS = (
    '{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"unused","kty":"OKP",'
    '"use":"sig","x":"O-cX0g0xmFjyu_3CjAJd4swlM1Caf0u_X4JNwl6nEHs"}]}'
)
