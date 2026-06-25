# Attachment Mail ID Validation

Severity: Low

## Finding

`fetch_attachment` docs promise empty `mail_id` validation, but the implementation only validates `attachment.part_id`.

## Files

- `src/client.rs`

## TODO

- Either validate `mail_id.trim().is_empty()` or remove the docs claim.
- Prefer validation, since it fails before unnecessary network calls.
- Add one small unit test for empty `mail_id`.
