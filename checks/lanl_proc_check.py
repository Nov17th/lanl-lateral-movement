#!/usr/bin/env python3
"""Checks on proc before the team builds on it: day and host coverage, whether red team logons are followed
by process starts on the target host, and whether those processes are new to the host. Also sizes the
user-hour table that the Isolation Forest would run on.

    python lanl_check.py convert --only proc --data-dir DATA --out OUT
    python lanl_proc_check.py --out OUT --memory-limit 14GB

Reads the Parquet folders written by lanl_check.py convert and writes OUT/report_proc.md and
OUT/proc_coverage_by_day.csv.
"""
import argparse
import os

from lanl_check import HUMAN_OK, INFO, PASS, WARN, Report, connect, sql_path

WINDOW = 600       # seconds after a logon in which a process start counts as following it
HISTORY_DAYS = 3   # logons on days 1-3 are skipped: with no history, every process looks new to the host


def pct(x):
    return f"{x:.1%}"


def main():
    ap = argparse.ArgumentParser(description="LANL proc checks")
    ap.add_argument("--out", required=True, help="folder written by lanl_check.py convert")
    ap.add_argument("--sample", type=int, default=20000, help="normal logons to compare against")
    ap.add_argument("--threads", type=int)
    ap.add_argument("--memory-limit", help="e.g. 14GB")
    a = ap.parse_args()
    a.data_dir = a.out
    con = connect(a)
    rep = Report("LANL proc checks")

    for name in ["auth", "redteam", "proc"]:
        d = os.path.join(a.out, name)
        if not os.path.isdir(d):
            step = "convert --only proc" if name == "proc" else "convert"
            raise SystemExit(f"{d} not found; run lanl_check.py {step} first")
        con.execute(f"CREATE VIEW {name} AS SELECT * FROM "
                    f"read_parquet('{sql_path(d)}/*/*.parquet', hive_partitioning=true)")

    # C1: rows and hosts per day; sparse days that overlap red team days matter most
    cov = con.execute("""SELECT day, count(*) AS rows, count(DISTINCT comp) AS hosts,
            count(*) FILTER (WHERE start_end = 'Start') AS starts
        FROM proc GROUP BY day ORDER BY day""").df()
    cov.to_csv(os.path.join(a.out, "proc_coverage_by_day.csv"), index=False)
    kinds = con.execute("SELECT start_end, count(*) FROM proc GROUP BY 1 ORDER BY 2 DESC").fetchall()
    rep.add("C1 proc rows", f"{int(cov['rows'].sum()):,} on {len(cov)} days; start_end: "
            + ", ".join(f"{k}={n:,}" for k, n in kinds), INFO)
    auth_days = con.execute("SELECT max(day) FROM auth").fetchone()[0]
    rt_days = {r[0] for r in con.execute("SELECT DISTINCT day FROM redteam").fetchall()}
    med = cov["rows"].median()
    sparse = set(cov.loc[cov["rows"] < 0.2 * med, "day"]) | (set(range(1, auth_days + 1)) - set(cov["day"]))
    gaps, gaps_rt = sorted(sparse), sorted(sparse & rt_days)
    rep.add("C1 proc coverage by day",
            "all days" if not gaps else f"missing or sparse days {gaps}"
            + (f"; red team days among them: {gaps_rt}" if gaps_rt else ""),
            PASS if not gaps_rt else WARN,
            "" if not gaps_rt else "the process tab can only cover the other red team days")

    # C2: do the hosts the attackers reached have any process data at all?
    con.execute("CREATE TEMP TABLE proc_hosts AS SELECT DISTINCT comp FROM proc")
    n_proc_hosts = con.execute("SELECT count(*) FROM proc_hosts").fetchone()[0]
    n_auth_hosts = con.execute("SELECT count(DISTINCT dst_comp) FROM auth WHERE auth_orient = 'LogOn'").fetchone()[0]
    rep.add("C2 hosts with process data", f"{n_proc_hosts:,} (hosts that receive logons: {n_auth_hosts:,})", INFO)
    n_rt, n_rt_cov = con.execute("""SELECT count(*), count(*) FILTER (WHERE comp IN (SELECT comp FROM proc_hosts))
        FROM (SELECT DISTINCT dst_comp AS comp FROM redteam)""").fetchone()
    rep.add("C2 red team target hosts with process data", f"{n_rt_cov}/{n_rt} ({pct(n_rt_cov / n_rt)})",
            PASS if n_rt_cov >= 0.5 * n_rt else WARN)
    src = con.execute("SELECT src_comp FROM redteam GROUP BY 1 ORDER BY count(*) DESC LIMIT 1").fetchone()[0]
    n_all, n_all_cov, n_unl, n_unl_cov = con.execute(f"""
        WITH t AS (SELECT DISTINCT dst_comp AS comp FROM auth
                   WHERE src_comp = '{src}' AND dst_comp <> '{src}' AND auth_orient = 'LogOn'),
             f AS (SELECT comp, comp IN (SELECT comp FROM proc_hosts) AS has_proc,
                          comp NOT IN (SELECT dst_comp FROM redteam) AS unlabelled FROM t)
        SELECT count(*), count(*) FILTER (WHERE has_proc),
               count(*) FILTER (WHERE unlabelled), count(*) FILTER (WHERE unlabelled AND has_proc) FROM f""").fetchone()
    rep.add(f"C2 hosts {src} logged on to, with process data",
            f"{n_all_cov}/{n_all}; of the {n_unl} not in the labels: {n_unl_cov}", INFO)

    # C3-C5: red team logons vs a sample of normal remote logons on the same days, excluding the red team
    # source hosts. For each logon: any process start on the target within WINDOW, one under the same
    # account, one that the host has never started before.
    con.execute(f"""CREATE TEMP TABLE ev AS
        SELECT row_number() OVER () AS id, * FROM (
            SELECT 'red team' AS grp, time, "user" AS logon_user, dst_comp AS comp, day
            FROM redteam WHERE day > {HISTORY_DAYS}
            UNION ALL
            SELECT 'normal', time, logon_user, comp, day FROM (
                SELECT time, src_user AS logon_user, dst_comp AS comp, day FROM auth
                WHERE {HUMAN_OK} AND auth_orient = 'LogOn' AND src_comp <> dst_comp
                  AND day > {HISTORY_DAYS} AND day IN (SELECT DISTINCT day FROM redteam)
                  AND src_comp NOT IN (SELECT DISTINCT src_comp FROM redteam)
            ) USING SAMPLE reservoir({int(a.sample)} ROWS) REPEATABLE (42))""")
    con.execute(f"""CREATE TEMP TABLE cand AS
        SELECT e.id, e.logon_user, p."user" AS proc_user, p.comp, p.proc, p.time
        FROM ev e JOIN proc p ON p.comp = e.comp AND p.day = e.day
        WHERE p.start_end = 'Start' AND p.time BETWEEN e.time AND e.time + {WINDOW}""")
    con.execute("""CREATE TEMP TABLE first_seen AS
        SELECT p.comp, p.proc, min(p.time) AS first_time
        FROM proc p JOIN (SELECT DISTINCT comp, proc FROM cand) k ON p.comp = k.comp AND p.proc = k.proc
        WHERE p.start_end = 'Start' GROUP BY 1, 2""")
    res = con.execute("""
        WITH per AS (
            SELECT c.id, bool_or(c.proc_user = c.logon_user) AS same_user, bool_or(f.first_time = c.time) AS new_proc
            FROM cand c JOIN first_seen f ON c.comp = f.comp AND c.proc = f.proc GROUP BY c.id)
        SELECT e.grp, count(*) AS n,
               avg(CASE WHEN per.id IS NOT NULL THEN 1.0 ELSE 0 END) AS any_proc,
               avg(CASE WHEN per.same_user THEN 1.0 ELSE 0 END) AS same_user,
               avg(CASE WHEN per.new_proc THEN 1.0 ELSE 0 END) AS new_proc
        FROM ev e LEFT JOIN per ON e.id = per.id GROUP BY e.grp""").df().set_index("grp")
    if "red team" not in res.index or "normal" not in res.index:
        rep.add("C3 logons compared", "no red team or no normal logons after the history days", WARN)
        rep.write(os.path.join(a.out, "report_proc.md"))
        return
    r, b = res.loc["red team"], res.loc["normal"]
    rep.note(f"Compared {int(r.n)} red team logons with {int(b.n)} sampled normal remote logons "
             f"(days {HISTORY_DAYS + 1}+ with red team activity; window {WINDOW // 60} min after the logon).")
    rep.add("C3 a process starts on the target within the window",
            f"red team {pct(r.any_proc)}, normal {pct(b.any_proc)}", PASS if r.any_proc >= 0.3 else WARN,
            "" if r.any_proc >= 0.3 else "too few red team steps have process data for a process tab")
    rep.add("C4 the process runs under the account that just logged on",
            f"red team {pct(r.same_user)}, normal {pct(b.same_user)}", INFO)
    ratio = r.new_proc / b.new_proc if b.new_proc > 0 else float("inf")
    rep.add("C5 the process is new to the host",
            f"red team {pct(r.new_proc)}, normal {pct(b.new_proc)}"
            + (f" ({ratio:.1f}x)" if ratio != float("inf") else ""),
            PASS if ratio >= 3 else WARN,
            "" if ratio >= 3 else "a rare-process signal is weak; show the process tab as context, not as a detector")

    # C6: size of the user-hour table the Isolation Forest would score, and how many red team user-hours it has
    n_uh = con.execute(f"""SELECT count(*) FROM (
        SELECT src_user, (time - 1) // 3600 AS hour FROM auth
        WHERE {HUMAN_OK} AND auth_orient = 'LogOn' GROUP BY 1, 2)""").fetchone()[0]
    n_rt_uh = con.execute("""SELECT count(*) FROM (
        SELECT DISTINCT "user", (time - 1) // 3600 FROM redteam)""").fetchone()[0]
    rep.add("C6 user-hour rows for the model", f"{n_uh:,}; red team user-hours: {n_rt_uh} ({n_rt_uh / n_uh:.4%})",
            INFO, "Isolation Forest trains on small subsamples, so the table size only affects scoring time")

    rep.write(os.path.join(a.out, "report_proc.md"))


if __name__ == "__main__":
    main()
