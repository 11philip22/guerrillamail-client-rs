# CI Format And Clippy

Severity: Low

## Finding

`cargo fmt --check` fails in `src/client.rs`, and strict clippy fails on doc continuation plus a collapsible `if`.

## Files

- `src/client.rs`

## TODO

- Run `cargo fmt`.
- Fix clippy warnings without adding allow attributes.
- Re-run `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings`.
