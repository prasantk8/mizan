# Identity verification-key rotation

Mizan verifies identity tokens from the public-only JSON document in `MIZAN_IDENTITY_JWKS`. It does
not fetch keys from a token header or from the network. The deployment mechanism may store this
document in a Kubernetes Secret, Compose environment file, or equivalent controlled configuration;
all replicas must receive the same reviewed document.

Each key requires a unique `kid`, `use: "sig"`, and one of `RS256`, `ES256`, or `EdDSA`. Keep only
public parameters. A minimal Ed25519 document has this shape:

```json
{"keys":[{"kid":"identity-2026-09","kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","x":"<base64url public key>"}]}
```

## Planned rotation

Record the old `kid`, new `kid`, change owner, start time, and the configured
`MIZAN_IDENTITY_TOKEN_MAX_TTL_SECONDS`. Then:

1. Export the IdP's old and new public JWKs into one `keys` array. Reject the change if identifiers
   collide, private parameters appear, or the declared algorithm is not the key's algorithm.
2. Roll out the overlap document to every Mizan replica. Do not switch the IdP yet. Check that an
   old-key token and a controlled new-key token both authenticate on every replica.
3. Switch the IdP to sign with the new `kid`. Record the last time the old key could have issued a
   token. Keep both public keys deployed.
4. Wait at least `MIZAN_IDENTITY_TOKEN_MAX_TTL_SECONDS` from that recorded time. The bound is why an
   old token cannot remain legitimately live past the overlap.
5. Remove the old JWK and roll out the new-only document. Verify a new-key token succeeds and a
   freshly signed test token naming the retired `kid` receives 401 `identity_token_kid_unknown`.

If step 2 fails, restore the old-only document; the IdP still signs with the old key. If step 5
causes an unexpected refusal, restore the overlap document while investigating. Do not restore a
key retired because compromise is suspected: emergency retirement deliberately trades continuity
for containment and happens immediately, without waiting for the overlap.

Run the exact CI drill locally with:

```console
uv run --frozen python scripts/identity_key_rotation_drill.py
```

It exercises the shipped verifier through old-only, overlap, and new-only states. The final state
must accept the new key and refuse the retired `kid`; any other outcome exits non-zero.
