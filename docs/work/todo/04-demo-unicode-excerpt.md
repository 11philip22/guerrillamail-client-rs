# Demo Unicode Excerpt

Severity: Medium

## Finding

The demo slices `mail_excerpt` by byte index, which can panic when the excerpt contains non-ASCII text.

## Files

- `examples/demo.rs`

## TODO

- Replace byte slicing with `.chars().take(80).collect::<String>()`.
- Keep the output behavior otherwise unchanged.
