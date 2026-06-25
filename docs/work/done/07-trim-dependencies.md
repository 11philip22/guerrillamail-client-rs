# Trim Dependencies

Severity: Low

## Finding

The crate ships avoidable normal dependency cost: `rand` is example-only, `tokio/full` is heavier than needed, `socks` is always enabled, and `regex` handles one token scrape.

## Files

- `Cargo.toml`
- `src/client.rs`
- `examples/demo.rs`

## TODO

- Move `rand` to `dev-dependencies` if it is only used by the example.
- Reduce `tokio` features to what the crate and tests actually need.
- Consider making SOCKS proxy support feature-gated.
- Replace the token regex with simple string parsing if it stays readable.
