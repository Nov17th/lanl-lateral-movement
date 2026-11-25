# LANL proc checks

2026-11-21 11:31

| Check | Result | Status | Action |
|---|---|---|---|
| C1 proc rows | 426,045,096 on 58 days; start_end: Start=335,842,571, End=90,202,525 | INFO |  |
| C1 proc coverage by day | all days | PASS |  |
| C2 hosts with process data | 11,960 (hosts that receive logons: 12,837) | INFO |  |
| C2 red team target hosts with process data | 264/301 (87.7%) | PASS |  |
| C2 hosts C17693 logged on to, with process data | 478/534; of the 243 not in the labels: 220 | INFO |  |
| C3 a process starts on the target within the window | red team 82.3%, normal 47.6% | PASS |  |
| C4 the process runs under the account that just logged on | red team 9.8%, normal 0.1% | INFO |  |
| C5 the process is new to the host | red team 36.0%, normal 0.6% (55.9x) | PASS |  |
| C6 user-hour rows for the model | 6,470,013; red team user-hours: 282 (0.0044%) | INFO | Isolation Forest trains on small subsamples, so the table size only affects scoring time |

## Notes

- Compared 724 red team logons with 20000 sampled normal remote logons (days 4+ with red team activity; window 10 min after the logon).
