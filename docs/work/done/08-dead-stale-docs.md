# Dead And Stale Docs

Severity: Low

## Finding

There are stale or dead references: `DomainParse` exists without a domain API, the demo claims domain listing, and README installation points at `0.7.1` while the crate is `0.7.2`.

## Files

- `src/error.rs`
- `examples/demo.rs`
- `README.md`

## TODO

- Delete `DomainParse` unless a domain-listing API is restored.
- Remove the demo claim about viewing available domains.
- Update the README install version to match `Cargo.toml`.
