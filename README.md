# login-log-analyser

A small Python tool for analyzing CSV login logs and highlighting suspicious
login activity.

## Run

From the project directory, run:

```powershell
python main.py
```

The sample input is `data/sample_logins.csv`. Each row should have these
columns:

```csv
timestamp,username,ip_address,status
2026-10-29T08:00:12Z,alice,192.0.2.10,success
2026-10-29T08:03:41Z,bob,198.51.100.24,failed
```

Statuses are case-insensitive and whitespace is ignored. Only `success` and
`failed` are accepted; an unknown status reports its CSV line number and stops
analysis.

## Checks

- Reports five failed logins for the same user and IP within five minutes.
- Reports a successful login for that user and IP after five or more recent
  failures.
- Reports an IP that attempts logins for more than five distinct usernames in
  any five-minute window. Both successful and failed attempts count. This
  five-minute username alert is emitted only once per IP for the entire file.
- Reports an IP that appears with more than five distinct usernames across the
  whole file, regardless of the time between attempts.

The analyzer also prints per-IP totals for failed and successful attempts and
the number of unique usernames.
