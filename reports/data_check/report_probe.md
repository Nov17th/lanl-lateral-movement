# LANL probe

2026-11-19 14:30

| Check | Result | Status | Action |
|---|---|---|---|
| P1 red team edges (user, target) | 440 edges for 749 events; new at first red team use 216/440 (49%), used before 220, not in human auth 4; after warm-up 212/425 (50%) | INFO |  |
| P2 new edges per day, days 4-30 | median 4,165 edges from 1,971 users | INFO |  |
| P2 new edges per day, days 31-58 | median 2,860 edges from 1,440 users | INFO |  |
| P3 red team steps with a flow, days 1-15 | same direction 5 min 7/663 (1%); either direction 5 min 7/663 (1%), 1 h 56/663 (8%), 1 day 58/663 (9%) | INFO |  |
| P3 ordinary network logons with a flow, days 1-15 | either direction 5 min 123/2000 (6%) (random sample) | INFO |  |
| P3 flows of red team source hosts (as source / as target) | C17693: 238,537 / 1,427, C18025: 9 / 8, C19932: 10 / 10, C22409: 1,015 / 0 | INFO |  |
| P3 red team targets seen in flows at all | 201/291 (69%) | INFO |  |
| P5 SMB/RPC fan-out per host-day, days 1-15 | 99th percentile across hosts: 9 targets (median over days) | INFO |  |
| P5 red team source hosts: events; fan-out on red team days vs other days | C17693: 701 events, 14 (rank 99%) vs 0 (rank 0%); C22409: 26 events, 4 (rank 88%) vs 0 (rank 0%); C19932: 19 events, 1 (rank 0%) vs 0 (rank 0%); C18025: 3 events, 0 (rank 0%) vs 0 (rank 0%) | INFO |  |
| P4 red team steps with a DNS lookup of the target, days 27-58 | 5 min 0/54 (0%), 1 h 2/54 (4%), 1 day 4/54 (7%) | INFO |  |
| P4 ordinary network logons with a DNS lookup, days 27-58 | 5 min 187/2000 (9%) (random sample) | INFO |  |
