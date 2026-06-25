# Default TLS Verification

Severity: High

## Finding

`ClientBuilder::new` defaults `danger_accept_invalid_certs` to `true`, so normal clients skip TLS certificate validation.

## Files

- `src/client.rs`

## TODO

- Change the default to `false`.
- Keep `danger_accept_invalid_certs(true)` as the explicit opt-in path.
- Update docs that describe the default.
- Add the smallest builder test that locks the default.
