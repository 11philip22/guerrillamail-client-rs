# README Quick Start Move

Severity: Medium

## Finding

The README quick start loops over `messages` by value, then calls `messages.first()` afterward, so the example does not compile.

## Files

- `README.md`

## TODO

- Change `for msg in messages` to `for msg in &messages`.
- Run doctest-style validation manually or move the snippet into a tested doc example.
