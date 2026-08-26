# T-058 deterministic evidence-mutation findings

The committed pre-fix result is `docs/reviews/T-058-mutation-prefix-8cab423.json`. It records every
case generated with seed `58058`: sixteen offsets per required bundle file, with low-bit flip,
deletion, and space insertion at each offset. The gate has a fixed maximum of 288 verifier
invocations, each with a five-second timeout; it performs no network access.

## Disposition

The first run found three integrity holes, all at `manifest.json:568`: flip, deletion, and insertion
inside `hash_algorithm` changed the parsed value while the verifier still exited zero. The manifest
declared its algorithms but the verifier used constants without checking the declarations. Bundle
1.0 now requires the declared `canonicalization` and `hash_algorithm` values exactly; these three
mutations return `MALFORMED`.

The same run enumerated 38 misclassified detections. Each made one of the six JSON documents
syntactically malformed, but mutations outside `manifest.json` reached the whole-file checksum before
the parser and returned `INVALID`. That wrongly accused evidence when the input was not a bundle.
All required JSON documents are now parsed before evidence checks, and parse failures return
`MALFORMED`. The exact 38 case identifiers and their old/new verdict expectation remain in the
pre-fix result rather than being summarized away.

One exit-zero survivor, `manifest.json:34:insert-space`, was benign: the parsed JSON value was byte-for-
byte semantically identical after parsing. It remains enumerated in the current committed result as
`benign-semantically-identical`; the sample was not narrowed to remove it. Any exit-zero mutation that
changes the parsed value is an integrity hole and fails CI. Any syntactically malformed mutation not
reported as `MALFORMED` also fails CI.

This property complements rather than replaces T-040: T-058 samples byte edits nobody selected for
their attack meaning, while T-040 remains the named adversary drill.
