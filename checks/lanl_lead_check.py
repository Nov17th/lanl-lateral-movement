#!/usr/bin/env python3
"""Timing of the main red team source host per day: first and last outgoing logon, first labelled step,
and the gap since its previous active day ended. A small gap means the activity runs across the day
boundary, so a long "lead" on that day is an artifact of how days are cut.

    python lanl_lead_check.py --out OUT
    python lanl_lead_check.py --out OUT --host C17693 --days 6,7
"""
import argparse

import duckdb

ap = argparse.ArgumentParser(description="per-day timing of one source host")
ap.add_argument("--out", required=True, help="folder written by lanl_check.py convert")
ap.add_argument("--host", default="C17693")
ap.add_argument("--days", default="6,7", help="days to show hour by hour")
a = ap.parse_args()

base = a.out.replace("\\", "/").rstrip("/")
A = f"read_parquet('{base}/auth/*/*.parquet', hive_partitioning=true)"
R = f"read_parquet('{base}/redteam/*/*.parquet', hive_partitioning=true)"
OUT_LOGONS = f"src_comp = '{a.host}' AND dst_comp <> '{a.host}' AND auth_orient = 'LogOn'"
con = duckdb.connect()

print(f"\n{a.host}: outgoing logons and labelled steps per day (hours are within the day, 0-24)")
con.sql(f"""
WITH a AS (SELECT day, min(time) AS t0, max(time) AS t1, count(*) AS logons
           FROM {A} WHERE {OUT_LOGONS} GROUP BY day),
     r AS (SELECT day, min(time) AS tl, count(*) AS labels
           FROM {R} WHERE src_comp = '{a.host}' GROUP BY day)
SELECT a.day, a.logons, coalesce(r.labels, 0) AS labels,
       round(((a.t0 - 1) % 86400) / 3600, 1) AS first_logon_h,
       round(((r.tl - 1) % 86400) / 3600, 1) AS first_label_h,
       round(((a.t1 - 1) % 86400) / 3600, 1) AS last_logon_h,
       round((r.tl - a.t0) / 3600, 2) AS lead_h,
       lag(a.day) OVER (ORDER BY a.day) AS prev_day,
       round((a.t0 - lag(a.t1) OVER (ORDER BY a.day)) / 3600, 2) AS gap_from_prev_h
FROM a LEFT JOIN r USING (day) ORDER BY a.day
""").show(max_rows=60)

days = ", ".join(str(int(d)) for d in a.days.split(",") if d.strip())
print(f"\n{a.host}: hour by hour on days {days}")
con.sql(f"""
WITH a AS (SELECT day, CAST(((time - 1) % 86400) // 3600 AS INTEGER) AS hour,
                  count(*) AS logons, count(DISTINCT dst_comp) AS targets
           FROM {A} WHERE {OUT_LOGONS} AND day IN ({days}) GROUP BY ALL),
     r AS (SELECT day, CAST(((time - 1) % 86400) // 3600 AS INTEGER) AS hour, count(*) AS labels
           FROM {R} WHERE src_comp = '{a.host}' AND day IN ({days}) GROUP BY ALL)
SELECT day, hour, coalesce(a.logons, 0) AS logons, coalesce(a.targets, 0) AS targets,
       coalesce(r.labels, 0) AS labels
FROM a FULL JOIN r USING (day, hour) ORDER BY day, hour
""").show(max_rows=100)
