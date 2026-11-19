# LANL follow-up

2026-11-20 02:41

| Check | Result | Status | Action |
|---|---|---|---|
| F1 '?' share, LogOn | 468,170,253 rows; auth_type 0.0194% (90,613 rows), logon_type 0.0194% (90,616 rows) | INFO |  |
| F1 '?' share, LogOff | 436,100,783 rows; auth_type 100.0%, logon_type 0.0% | INFO |  |
| F1 '?' share, TGS | 99,003,278 rows; auth_type 100.0%, logon_type 100.0% | INFO |  |
| F1 '?' share, TGT | 38,390,589 rows; auth_type 100.0%, logon_type 100.0% | INFO |  |
| F1 '?' share, AuthMap | 9,571,401 rows; auth_type 100.0%, logon_type 100.0% | INFO |  |
| F1 '?' share, ScreenLock | 99,556 rows; auth_type 100.0%, logon_type 100.0% | INFO |  |
| F1 '?' share, ScreenUnlock | 94,599 rows; auth_type 100.0%, logon_type 100.0% | INFO |  |
| F1 '?' is all-or-nothing per event type | no, mixed in: LogOn | WARN | treat '?' in these event types as missing values |
| F1 auth rows in Parquet | 1,051,430,459 (expected 1,051,430,459) | PASS |  |
| F2 main red team source host | C17693: 701/749 labelled events | INFO |  |
| F2 days C17693 logs on to other hosts | 17 of 58; 14 of them have red team events; other days: 4 logons in total | INFO |  |
| F2 red team days where outgoing logons start 15+ min before the first labelled step | 6 of 14; from 18 min to 8.75 h (day 7) | INFO | look back before the alert when scoping (Q4) |
| F2 hosts C17693 logged on to, and how many appear in the labels | 534 hosts, 291 labelled, 243 never labelled | INFO | precision measured against the labels is a lower bound; review unlabelled targets by hand |
