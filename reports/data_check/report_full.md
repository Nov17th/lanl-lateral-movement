# LANL full data checks

2026-11-19 14:02

| Check | Result | Status | Action |
|---|---|---|---|
| D1 red team in range | 749 events on 18 days | PASS |  |
| D3 auth coverage | all days | PASS |  |
| D3 flows coverage | missing or sparse days [18, 19, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58]; red team days among them: [27, 28, 29, 30] | WARN | Q1 and Q5 only on covered days |
| D3 dns coverage | missing or sparse days [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]; red team days among them: [2, 3, 6, 7, 8, 9, 10, 13, 14, 15, 16, 21, 22, 23] | WARN | Q5 uses flows only on these days |
| D5 '?' in auth | auth_type=55.48%, logon_type=14.00% | INFO |  |
| D5 non-human accounts | 67.5% of 1,051,430,459 events | INFO |  |
| D5 human successful logons | 331,860,902 | PASS |  |
| D2 red team matches auth | exact 735/749 (98%), within 60s 735/749 | PASS |  |
| D4 autocorrelation of hourly auth | lag 24h 0.70, lag 7d 0.71 | PASS |  |
| D6 new-edge lift (warm-up 3 days) | red team 214/724 = 29.6%, normal 0.07%, lift 426.7, 4 unmatched | PASS |  |
| D7 NTLM share | red team 100%, normal 3% | INFO |  |
| D7 red team source hosts | 4 | INFO |  |
| D8 admin ports in flows | 445: 25,912,435, 80: 4,811,435, 139: 2,123,849, 135: 1,002,218, 443: 898,289, 22: 652,179 | INFO |  |
| D9 red team events with a flow within 5 min | 7/749 (1%) | WARN | Q5 becomes side information in V3 |
| G1 Parquet size | auth: 8.0 GB, flows: 1.1 GB, dns: 132.8 MB, redteam: 18.7 KB | INFO |  |
| G1 query time, distinct targets per user-day | 17.9s | PASS |  |

## Notes

- Rows per day: out\coverage_by_day.csv
- Busiest relative hours: 9, 10, 8, 14, 11, 13
- Data verdict: GO WITH CONDITIONS. Warnings: D3 flows coverage; D3 dns coverage; D9 red team events with a flow within 5 min
