# LANL quick check

2026-11-19 13:36

| Check | Result | Status | Action |
|---|---|---|---|
| G1 auth size | 7.1 GB | PASS |  |
| G1 proc size | 2.2 GB | PASS |  |
| G1 flows size | 1.0 GB | PASS |  |
| G1 dns size | 176.5 MB | PASS |  |
| G1 redteam size | 4.7 KB | PASS |  |
| G1 free disk | 332.9 GB | PASS |  |
| D1 red team size | 749 events, 104 users, 301 targets, 181 user-days, days 2-30 | PASS |  |
| D1 red team within --days | last day 30, --days 58 | PASS |  |
| D7 red team source hosts | 4 | INFO |  |
| G1 auth conversion estimate | 5,000,000 rows in 1.5s, ~0.1 h total | PASS |  |
| D5 '?' in auth sample | auth_type=58.4%, logon_type=17.5% | INFO |  |
| D5 non-human accounts in sample | 71.1% | INFO |  |
| D5 unparseable time in sample | 0 | PASS |  |
| D8 admin ports in flows sample | 445: 232,577, 80: 112,664, 139: 33,088, 22: 31,068, 135: 21,052, 443: 15,045 | INFO |  |

## Notes

- Red team events per day: 2: 10, 3: 15, 6: 21, 7: 3, 8: 1, 9: 273, 10: 15, 13: 209, 14: 81, 15: 35, 16: 26, 21: 1, 22: 4, 23: 1, 27: 26, 28: 9, 29: 3, 30: 16
- The sample is the first 5,000,000 rows of day 1; rates below only catch format problems.
- Auth types in sample: ?=2,921,308, Kerberos=1,725,002, NTLM=218,471, Negotiate=128,617, MICROSOFT_AUTHENTICATION_PACKAGE_V1_0=5,608, MICROSOFT_AUTHENTICATION_PACKAG=299
