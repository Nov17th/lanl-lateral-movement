#!/usr/bin/env python3
"""Follow-up probes after `lanl_check.py full`: red team edges, new-edge volume, flows/DNS around red team steps.

    python lanl_probe.py --out OUT --memory-limit 14GB

Reads the Parquet folders written by lanl_check.py convert and writes OUT/report_probe.md.
"""
import argparse
import os

import pandas as pd

from lanl_check import DAY, HUMAN_OK, INFO, Report, connect, sql_path

SAMPLE = 2000


def day_range(text):
    lo, hi = (int(x) for x in text.split("-"))
    return lo, hi


def pct(k, n):
    return f"{k}/{n} ({k / n:.0%})" if n else "0/0"


def match_counts(con, events, table, a_col, b_col, windows):
    """For each window (seconds), count events with a row in `table` linking src/dst within the window.
    `events` has id, time, src_comp, dst_comp, day. Flows are checked in both directions, DNS only src -> dst."""
    both = table == "flows"
    con.execute(f"""CREATE OR REPLACE TEMP TABLE hits AS
        SELECT e.id, abs(t.time - e.time) AS dt, 'same' AS dir FROM {events} e JOIN {table} t
          ON t.{a_col} = e.src_comp AND t.{b_col} = e.dst_comp AND t.day BETWEEN e.day - 1 AND e.day + 1
        {"" if not both else f'''UNION ALL
        SELECT e.id, abs(t.time - e.time), 'reverse' FROM {events} e JOIN {table} t
          ON t.{a_col} = e.dst_comp AND t.{b_col} = e.src_comp AND t.day BETWEEN e.day - 1 AND e.day + 1'''}""")
    out = {}
    for w in windows:
        out[w] = con.execute(f"SELECT count(DISTINCT id) FROM hits WHERE dt <= {w}").fetchone()[0]
    out["same_5m"] = con.execute("SELECT count(DISTINCT id) FROM hits WHERE dt <= 300 AND dir = 'same'").fetchone()[0]
    return out


def main():
    ap = argparse.ArgumentParser(description="LANL follow-up probes")
    ap.add_argument("--out", required=True, help="folder written by lanl_check.py convert")
    ap.add_argument("--flow-days", default="1-15", help="days with full flow volume")
    ap.add_argument("--dns-days", default="27-58", help="days with full DNS volume")
    ap.add_argument("--warmup-days", type=int, default=3)
    ap.add_argument("--threads", type=int)
    ap.add_argument("--memory-limit", help="e.g. 14GB")
    a = ap.parse_args()
    a.data_dir = a.out
    con = connect(a)
    rep = Report("LANL probe")

    for name in ["auth", "flows", "dns", "redteam"]:
        d = os.path.join(a.out, name)
        if not os.path.isdir(d):
            raise SystemExit(f"{d} not found; run lanl_check.py convert first")
        con.execute(f"CREATE VIEW {name} AS SELECT * FROM "
                    f"read_parquet('{sql_path(d)}/*/*.parquet', hive_partitioning=true)")
    con.execute('CREATE TEMP TABLE rt AS SELECT row_number() OVER () AS id, time, "user", src_comp, dst_comp, day '
                'FROM redteam')
    warmup = a.warmup_days * DAY

    # P1: red team per distinct (user, target) edge rather than per event
    con.execute(f"""CREATE TEMP TABLE edge_first AS SELECT src_user, dst_comp, min(time) AS first_seen
                    FROM auth WHERE {HUMAN_OK} GROUP BY ALL""")
    n_edges, new, seen, missing, new_late, n_late = con.execute(f"""
        WITH e AS (SELECT "user", dst_comp, min(time) AS t FROM rt GROUP BY ALL)
        SELECT count(*), count(*) FILTER (WHERE f.first_seen = e.t), count(*) FILTER (WHERE f.first_seen < e.t),
               count(*) FILTER (WHERE f.first_seen IS NULL OR f.first_seen > e.t),
               count(*) FILTER (WHERE f.first_seen = e.t AND e.t > {warmup}), count(*) FILTER (WHERE e.t > {warmup})
        FROM e LEFT JOIN edge_first f ON f.src_user = e."user" AND f.dst_comp = e.dst_comp""").fetchone()
    n_rt = con.execute("SELECT count(*) FROM rt").fetchone()[0]
    rep.add("P1 red team edges (user, target)",
            f"{n_edges} edges for {n_rt} events; new at first red team use {pct(new, n_edges)}, "
            f"used before {seen}, not in human auth {missing}; after warm-up {pct(new_late, n_late)}", INFO)

    # P2: how many new edges ordinary activity produces per day (what a naive "first logon" rule would raise)
    per_day = con.execute(f"""SELECT CAST((first_seen - 1) // {DAY} + 1 AS INTEGER) AS day,
            count(*) AS edges, count(DISTINCT src_user) AS users
        FROM edge_first WHERE first_seen > {warmup} GROUP BY 1""").df()
    for lo, hi in [(a.warmup_days + 1, 30), (31, 58)]:
        part = per_day[per_day["day"].between(lo, hi)]
        if len(part):
            rep.add(f"P2 new edges per day, days {lo}-{hi}",
                    f"median {part['edges'].median():,.0f} edges from {part['users'].median():,.0f} users", INFO)
    per_day.sort_values("day").to_csv(os.path.join(a.out, "new_edges_by_day.csv"), index=False)

    # Baseline: ordinary human network logons (different source and target) sampled from the same days
    def baseline(lo, hi, name):
        con.execute(f"""CREATE OR REPLACE TEMP TABLE {name} AS
            SELECT row_number() OVER () AS id, time, src_comp, dst_comp, day FROM (
                SELECT time, src_comp, dst_comp, day FROM auth
                WHERE {HUMAN_OK} AND src_comp <> dst_comp AND auth_orient = 'LogOn' AND day BETWEEN {lo} AND {hi}
            ) USING SAMPLE reservoir({SAMPLE} ROWS) REPEATABLE (42)""")

    # P3: flows around red team steps on days with full flow volume
    flo, fhi = day_range(a.flow_days)
    con.execute(f"CREATE TEMP TABLE rt_f AS SELECT * FROM rt WHERE day BETWEEN {flo} AND {fhi}")
    n_f = con.execute("SELECT count(*) FROM rt_f").fetchone()[0]
    if n_f:
        m = match_counts(con, "rt_f", "flows", "src_comp", "dst_comp", [300, 3600, DAY])
        baseline(flo, fhi, "base_f")
        b = match_counts(con, "base_f", "flows", "src_comp", "dst_comp", [300])
        rep.add(f"P3 red team steps with a flow, days {flo}-{fhi}",
                f"same direction 5 min {pct(m['same_5m'], n_f)}; either direction 5 min {pct(m[300], n_f)}, "
                f"1 h {pct(m[3600], n_f)}, 1 day {pct(m[DAY], n_f)}", INFO)
        rep.add(f"P3 ordinary network logons with a flow, days {flo}-{fhi}",
                f"either direction 5 min {pct(b[300], SAMPLE)} (random sample)", INFO)
        hosts = con.execute(f"""WITH h AS (SELECT DISTINCT src_comp AS comp FROM rt_f),
            f AS (SELECT src_comp AS comp, 1 AS s, 0 AS d FROM flows
                  WHERE day BETWEEN {flo} AND {fhi} AND src_comp IN (SELECT comp FROM h)
                  UNION ALL
                  SELECT dst_comp, 0, 1 FROM flows WHERE day BETWEEN {flo} AND {fhi} AND dst_comp IN (SELECT comp FROM h))
            SELECT h.comp, coalesce(sum(f.s), 0), coalesce(sum(f.d), 0) FROM h LEFT JOIN f USING (comp)
            GROUP BY 1 ORDER BY 1""").fetchall()
        rep.add("P3 flows of red team source hosts (as source / as target)",
                ", ".join(f"{c}: {s:,} / {d:,}" for c, s, d in hosts), INFO)
        n_t, n_t_seen = con.execute(f"""WITH t AS (SELECT DISTINCT dst_comp AS comp FROM rt_f)
            SELECT count(*), count(*) FILTER (WHERE comp IN (
                SELECT src_comp FROM flows WHERE day BETWEEN {flo} AND {fhi}
                UNION SELECT dst_comp FROM flows WHERE day BETWEEN {flo} AND {fhi})) FROM t""").fetchone()
        rep.add("P3 red team targets seen in flows at all", pct(n_t_seen, n_t), INFO)

        # P5: host-level behaviour. Fan-out = distinct hosts a source reaches on SMB/RPC ports in a day,
        # ranked against every host active that day.
        con.execute(f"""CREATE TEMP TABLE fan AS
            SELECT day, src_comp, count(DISTINCT dst_comp) AS fanout FROM flows
            WHERE day BETWEEN {flo} AND {fhi} AND dst_port IN ('135', '139', '445') GROUP BY ALL""")
        con.execute("CREATE TEMP TABLE fan_rank AS "
                    "SELECT *, percent_rank() OVER (PARTITION BY day ORDER BY fanout) AS pr FROM fan")
        p99 = con.execute("SELECT median(q) FROM (SELECT quantile_cont(fanout, 0.99) AS q FROM fan GROUP BY day)"
                          ).fetchone()[0]
        rep.add(f"P5 SMB/RPC fan-out per host-day, days {flo}-{fhi}",
                f"99th percentile across hosts: {p99 or 0:.0f} targets (median over days)", INFO)
        hosts = con.execute(f"""WITH h AS (SELECT src_comp, count(*) AS events, list(DISTINCT day) AS days
                                          FROM rt GROUP BY 1),
            d AS (SELECT h.src_comp, g.day, coalesce(f.fanout, 0) AS fanout, coalesce(f.pr, 0) AS pr,
                         list_contains(h.days, g.day) AS attack
                  FROM h CROSS JOIN range({flo}, {fhi} + 1) AS g(day)
                  LEFT JOIN fan_rank f ON f.src_comp = h.src_comp AND f.day = g.day)
            SELECT h.src_comp, h.events,
                   median(d.fanout) FILTER (WHERE d.attack), median(d.pr) FILTER (WHERE d.attack),
                   median(d.fanout) FILTER (WHERE NOT d.attack), median(d.pr) FILTER (WHERE NOT d.attack)
            FROM h JOIN d USING (src_comp) GROUP BY 1, 2 ORDER BY 2 DESC""").fetchall()

        def fmt(fan, rank):
            return "n/a" if fan is None else f"{fan:.0f} (rank {rank:.0%})"
        rep.add("P5 red team source hosts: events; fan-out on red team days vs other days",
                "; ".join(f"{c}: {ev} events, {fmt(fa, pa)} vs {fmt(fo, po)}" for c, ev, fa, pa, fo, po in hosts),
                INFO)

    # P4: DNS lookups of the target by the source around red team steps, on days with full DNS volume
    dlo, dhi = day_range(a.dns_days)
    con.execute(f"CREATE TEMP TABLE rt_d AS SELECT * FROM rt WHERE day BETWEEN {dlo} AND {dhi}")
    n_d = con.execute("SELECT count(*) FROM rt_d").fetchone()[0]
    if n_d:
        m = match_counts(con, "rt_d", "dns", "src_comp", "resolved_comp", [300, 3600, DAY])
        baseline(dlo, dhi, "base_d")
        b = match_counts(con, "base_d", "dns", "src_comp", "resolved_comp", [300])
        rep.add(f"P4 red team steps with a DNS lookup of the target, days {dlo}-{dhi}",
                f"5 min {pct(m[300], n_d)}, 1 h {pct(m[3600], n_d)}, 1 day {pct(m[DAY], n_d)}", INFO)
        rep.add(f"P4 ordinary network logons with a DNS lookup, days {dlo}-{dhi}",
                f"5 min {pct(b[300], SAMPLE)} (random sample)", INFO)
    else:
        rep.add(f"P4 red team steps on days {dlo}-{dhi}", "none", INFO)

    rep.write(os.path.join(a.out, "report_probe.md"))


if __name__ == "__main__":
    main()
