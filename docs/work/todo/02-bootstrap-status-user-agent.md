# Bootstrap Status And User Agent

Severity: Medium

## Finding

The bootstrap request does not call `error_for_status()` and does not apply the configured user agent, even though docs say non-2xx bootstrap responses become `Error::Request`.

## Files

- `src/client.rs`

## TODO

- Apply the configured user agent to the bootstrap GET.
- Call `error_for_status()` before reading the response body.
- Add one mock-backed test for a non-2xx bootstrap response.
