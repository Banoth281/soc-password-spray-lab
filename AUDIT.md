# Audit record - 18 October 2026

## Baseline
Inspected all six original repository files. The existing detector already counted distinct accounts, normalised timestamps, sorted events, handled inclusive windows, suppressed active alerts, and supplied eight passing tests.

## Changes
- Reject duplicate CSV header names to avoid ambiguous field selection.
- Reject missing/extra row fields explicitly.
- Report physical CSV line numbers using csv.DictReader.line_num.
- Exclude exact normalised duplicate events with reported rejection reasons.
- Prevent CLI output from resolving to the input CSV.
- Convert output-write errors into clear CLI errors.
- Expand from eight to 18 tests and add Windows/Linux CI.

## Validation
Local execution: python -m unittest -v -> 18 tests passed.
Baseline: eight existing tests passed before changes.
The regression test regenerates the supplied report and compares the complete parsed JSON with alerts.json. Result unchanged: 12 valid events, zero rejected rows, one alert at 10:02:00 UTC for five accounts from 198.51.100.25.

Added tests cover missing/duplicate headers, normalised duplicate exclusion, malformed field counts, invalid IP/account/result, multiline row locations, empty input, invalid settings, input-file protection, and exact sample-report parity.

## Design limits
Normalised duplicate identity is timestamp/account/source/result. Distinct events with identical values cannot be separated without stable event IDs. Accounts are case-sensitive and no tenant/domain context is supplied. Direct detect() inputs are assumed valid and unique; validation and deduplication occur in read_events(). Shared gateways can create benign patterns. No passwords, MFA, sessions, or live containment evidence exists.

An output symlink resolving directly to the input is rejected; hard-link aliases are not explicitly detected. Future work can add stable event IDs and tenant/application grouping. Tests do not establish production detection accuracy.

## Hosted verification
All 18 tests passed on both windows-latest and ubuntu-latest in [run 39117120851](https://github.com/Banoth281/soc-password-spray-lab/actions/runs/39117120851), testing commit 759fae6136a103cc95b95f67371de5b02e103cff. Both jobs completed successfully. No real authentication attempts were generated.
