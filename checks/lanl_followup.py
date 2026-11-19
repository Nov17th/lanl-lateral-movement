#!/usr/bin/env python3
"""Follow-up checks after `lanl_probe.py`: what "?" means in auth, and how much of the main attacker host's
activity the red team labels cover.

    python lanl_followup.py --out OUT --memory-limit 14GB

Reads the Parquet folders written by lanl_check.py convert and writes OUT/report_followup.md
and OUT/attacker_host_by_day.csv.
"""
import argparse
import os

from lanl_check import AUTH_ROWS, FAIL, INFO, PASS, WARN, Report, connect, sql_path


def main():
    ap = argparse.ArgumentParser(description="LANL follow-up checks")
    ap.add_argument("--out", required=True, help="folder written by lanl_check.py convert")
    ap.add_argument("--threads", type=int)
    ap.add_argument("--memory-limit", help="e.g. 14GB")
    a = ap.parse_args()
    a.data_dir = a.out
    con = connect(a)
    rep = Report("LANL follow-up")

    for name in ["auth", "redteam"]:
        d = os.path.join(a.out, name)
        if not os.path.isdir(d):
            raise SystemExit(f"{d} not found; run lanl_check.py convert first")
        con.execute(f"CREATE VIEW {name} AS SELECT * FROM "
                    f"read_parquet('{sql_path(d)}/*/*.parquet', hive_partitioning=true)")

    # F1: "?" in auth_type / logon_type by event type. If it is 0% or 100% per type, it means
    # "field does not apply to this event type", not missing data.
    rows = con.execute("""SELECT auth_orient, count(*) AS n,
            count(*) FILTER (WHERE auth_type = '?') AS q_auth,
            count(*) FILTER (WHERE logon_type = '?') AS q_logon
        FROM auth GROUP BY 1 ORDER BY n DESC""").fetchall()

    def share(k, n):
        return f"{k / n:.1%}" if k in (0, n) else f"{k / n:.4%} ({k:,} rows)"
    for orient, n, qa, ql in rows:
        rep.add(f"F1 '?' share, {orient}", f"{n:,} rows; auth_type {share(qa, n)}, logon_type {share(ql, n)}", INFO)
    mixed = [o for o, n, qa, ql in rows if 0 < qa < n or 0 < ql < n]
    rep.add("F1 '?' is all-or-nothing per event type",
            "yes" if not mixed else f"no, mixed in: {', '.join(mixed)}", PASS if not mixed else WARN,
            "" if not mixed else "treat '?' in these event types as missing values")
    total = sum(r[1] for r in rows)
    rep.add("F1 auth rows in Parquet", f"{total:,} (expected {AUTH_ROWS:,})", PASS if total == AUTH_ROWS else FAIL)

    # F2: the red team source host with the most labelled events, and everything it logged on to
    src, n_src, n_rt = con.execute("""SELECT src_comp, count(*), sum(count(*)) OVER () FROM redteam
        GROUP BY 1 ORDER BY 2 DESC LIMIT 1""").fetchone()
    rep.add("F2 main red team source host", f"{src}: {n_src}/{n_rt} labelled events", INFO)

    con.execute(f"""CREATE TEMP TABLE out_logons AS
        SELECT day, time, src_user, dst_comp FROM auth
        WHERE src_comp = '{src}' AND dst_comp <> '{src}' AND auth_orient = 'LogOn'""")
    by_day = con.execute(f"""
        WITH a AS (SELECT day, count(*) AS logons, count(DISTINCT dst_comp) AS targets,
                          count(DISTINCT src_user) AS users, min(time) AS first_logon
                   FROM out_logons GROUP BY 1),
             r AS (SELECT day, count(*) AS rt_events, min(time) AS first_label
                   FROM redteam WHERE src_comp = '{src}' GROUP BY 1)
        SELECT coalesce(a.day, r.day) AS day, coalesce(a.logons, 0) AS logons, coalesce(a.targets, 0) AS targets,
               coalesce(a.users, 0) AS users, coalesce(r.rt_events, 0) AS rt_events,
               r.first_label - a.first_logon AS lead_seconds
        FROM a FULL JOIN r ON a.day = r.day ORDER BY 1""").df()
    by_day.to_csv(os.path.join(a.out, "attacker_host_by_day.csv"), index=False)

    n_days = con.execute("SELECT count(DISTINCT day) FROM auth").fetchone()[0]
    active = by_day[by_day["logons"] > 0]
    quiet = active[active["rt_events"] == 0]
    rep.add(f"F2 days {src} logs on to other hosts",
            f"{len(active)} of {n_days}; {len(active) - len(quiet)} of them have red team events; "
            f"other days: {int(quiet['logons'].sum())} logons in total", INFO)
    lead = by_day.dropna(subset=["lead_seconds"])
    early = lead[lead["lead_seconds"] >= 900]
    if len(early):
        longest = early.loc[early["lead_seconds"].idxmax()]
        rep.add("F2 red team days where outgoing logons start 15+ min before the first labelled step",
                f"{len(early)} of {len(lead)}; from {early['lead_seconds'].min() / 60:.0f} min "
                f"to {longest['lead_seconds'] / 3600:.2f} h (day {int(longest['day'])})", INFO,
                "look back before the alert when scoping (Q4)")
    else:
        rep.add("F2 red team days where outgoing logons start 15+ min before the first labelled step",
                f"none of {len(lead)}", INFO)

    touched, labelled = con.execute("""WITH t AS (SELECT DISTINCT dst_comp FROM out_logons),
            l AS (SELECT DISTINCT dst_comp FROM redteam)
        SELECT count(*), count(l.dst_comp) FROM t LEFT JOIN l USING (dst_comp)""").fetchone()
    rep.add(f"F2 hosts {src} logged on to, and how many appear in the labels",
            f"{touched} hosts, {labelled} labelled, {touched - labelled} never labelled", INFO,
            "precision measured against the labels is a lower bound; review unlabelled targets by hand")

    rep.write(os.path.join(a.out, "report_followup.md"))


if __name__ == "__main__":
    main()
