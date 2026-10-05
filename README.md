# SOC Password Spray Detection Lab

A standalone SOC portfolio project using Python to identify a single source IP failing authentication against multiple accounts. Uses synthetic data; no login attempts are made.

## Investigation question

Is one source failing authentication against at least five distinct accounts within five minutes? This pattern may be consistent with password spraying, but these logs cannot establish whether the same password was attempted or whether malicious activity occurred.

## Run

Python 3.10 or newer. Standard library only.

From this project folder:

```bash
python detect_spray.py
python -m unittest -v
```

On Windows, replace `python` with `py` if needed.

Optional settings:

```bash
python detect_spray.py --threshold 5 --window-minutes 5 --output alerts.json
```

Each run replaces the output report. Invalid rows are excluded and reported with CSV line numbers; missing columns stop processing. Timestamps require timezone offsets and are normalised to UTC.

## Sample result

12 valid events, no rejected rows, one alert:

| Source IP | Detected at (UTC) | Distinct accounts | Failed attempts |
|---|---|---:|---:|
| 198.51.100.25 | 2026-10-05 10:02:00 | 5 | 5 |

The report is a snapshot when the threshold is crossed. A sixth account fails later and Alice subsequently logs in successfully. Those later events are not appended to the alert snapshot; review the original records during triage. The success alone does not prove compromise.

## Detection behaviour

- Sort events by timestamp and correlate failures by source IP.
- Count distinct accounts, not just failed attempts.
- Include failures exactly five minutes old; exclude older failures.
- Emit one alert per source while its observed rolling count remains at or above the threshold.
- Allow another alert after the count falls below the threshold and crosses it again.
- Successful events do not count as failures and do not clear other accounts' failures.

## Files

| File | Purpose |
|---|---|
| `detect_spray.py` | Detector, validation and JSON reporting |
| `login_events.csv` | Synthetic authentication records |
| `alerts.json` | Reproducible sample output |
| `test_detect_spray.py` | Eight behavioural tests |
| `investigation.md` | Evidence, alternative explanations and proposed triage |

## Limitations

Shared proxies or gateways can produce benign multi-account failures. Distributed sources and attempts spaced beyond the window can evade this rule. No password, MFA, device, reputation or session data is supplied. Account names are compared exactly as written. This is an offline learning detector, not a production SIEM integration.

## Skills demonstrated

Authentication analysis, event correlation, input validation, Python automation, structured alert reporting, testing and evidence-based SOC triage.
