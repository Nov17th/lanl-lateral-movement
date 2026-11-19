#!/usr/bin/env python3
"""Feasibility checks for the LANL multi-source cyber-security events dataset.

    pip install duckdb pandas numpy
    python lanl_check.py quick   --data-dir DATA --out OUT
    python lanl_check.py convert --data-dir DATA --out OUT    # hours; run overnight
    python lanl_check.py full    --data-dir DATA --out OUT

Each step writes report_<step>.md to OUT. Add a source later with: convert --only proc

Data: A. D. Kent, "Comprehensive, Multi-Source Cyber-Security Events", LANL, 2015 (CC0).
https://csr.lanl.gov/data/cyber1/
"""
import argparse
import os
import shutil
import sys
import time

import duckdb
import numpy as np
import pandas as pd

SCHEMAS = {
    "auth": ["time", "src_user", "dst_user", "src_comp", "dst_comp",
             "auth_type", "logon_type", "auth_orient", "outcome"],
    "proc": ["time", "user", "comp", "proc", "start_end"],
    "flows": ["time", "duration", "src_comp", "src_port", "dst_comp", "dst_port",
              "protocol", "packets", "bytes"],
    "dns": ["time", "src_comp", "resolved_comp"],
    "redteam": ["time", "user", "src_comp", "dst_comp"],
}
SELECT_EXPR = {
    "auth": "TRY_CAST(time AS BIGINT) AS time, src_user, dst_user, src_comp, dst_comp, "
            "auth_type, logon_type, auth_orient, outcome",
    "flows": "TRY_CAST(time AS BIGINT) AS time, TRY_CAST(duration AS BIGINT) AS duration, src_comp, src_port, "
             "dst_comp, dst_port, TRY_CAST(protocol AS INTEGER) AS protocol, "
             "TRY_CAST(packets AS BIGINT) AS packets, TRY_CAST(bytes AS BIGINT) AS bytes",
    "dns": "TRY_CAST(time AS BIGINT) AS time, src_comp, resolved_comp",
    "proc": "TRY_CAST(time AS BIGINT) AS time, \"user\", comp, proc, start_end",
    "redteam": "TRY_CAST(time AS BIGINT) AS time, \"user\", src_comp, dst_comp",
}
ALIASES = {"flows": ["flows", "flow"]}
REQUIRED = ("auth", "flows", "redteam")
EXPECTED_GZ_BYTES = {"auth": 7.2 * 2**30, "proc": 2.2 * 2**30, "flows": 1.1 * 2**30,
                     "dns": 177 * 2**20, "redteam": 4.8 * 2**10}  # sizes listed on the LANL page
AUTH_ROWS = 1_051_430_459  # from the README of g-research/dgraph-lanl-csr
DAY = 86400
ADMIN_PORTS = ["22", "135", "139", "445", "3389", "5985", "5986", "80", "443"]

# computer accounts (C123$@DOM), built-in service accounts, unknown user
NOISE_USER_SQL = """(src_user LIKE '%$@%' OR src_user LIKE 'SYSTEM@%' OR src_user LIKE 'ANONYMOUS LOGON@%'
    OR src_user LIKE 'LOCAL SERVICE@%' OR src_user LIKE 'NETWORK SERVICE@%' OR src_user = '?')"""
HUMAN_OK = f"outcome = 'Success' AND NOT {NOISE_USER_SQL}"

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"


def human(n):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def sql_path(path):
    return path.replace("\\", "/").replace("'", "''")


def find_file(data_dir, name):
    for base in ALIASES.get(name, [name]):
        for ext in (".txt.gz", ".txt", ".csv.gz", ".csv"):
            p = os.path.join(data_dir, base + ext)
            if os.path.exists(p):
                return p
    return None


def csv_src(path, name, rejects=False):
    cols = ", ".join(f"'{c}': 'VARCHAR'" for c in SCHEMAS[name])
    extra = ", store_rejects=true" if rejects else ""
    return f"read_csv('{sql_path(path)}', header=false, delim=',', auto_detect=false, columns={{{cols}}}{extra})"


def dir_size(path):
    return sum(os.path.getsize(os.path.join(root, f)) for root, _, files in os.walk(path) for f in files)


def port_list():
    return ",".join(f"'{p}'" for p in ADMIN_PORTS)


class Report:
    def __init__(self, title):
        self.title = title
        self.rows = []
        self.notes = []

    def add(self, check, result, status, action=""):
        self.rows.append((check, result, status, action))
        print(f"[{status}] {check}: {result}" + (f"\n    {action}" if action else ""))

    def note(self, text):
        self.notes.append(text)
        print(text)

    def write(self, path):
        def esc(s):
            return str(s).replace("|", "\\|").replace("\n", " ")
        lines = [f"# {self.title}", "", time.strftime("%Y-%m-%d %H:%M"), "",
                 "| Check | Result | Status | Action |", "|---|---|---|---|"]
        lines += [f"| {esc(c)} | {esc(r)} | {esc(s)} | {esc(a)} |" for c, r, s, a in self.rows]
        if self.notes:
            lines += ["", "## Notes", ""] + [f"- {n}" for n in self.notes]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"\nWrote {path}")


def connect(a):
    con = duckdb.connect()
    if a.threads:
        con.execute(f"SET threads={int(a.threads)}")
    if a.memory_limit:
        con.execute(f"SET memory_limit='{a.memory_limit}'")
    tmp = os.path.join(a.out or a.data_dir, ".duckdb_tmp")
    os.makedirs(tmp, exist_ok=True)
    con.execute(f"SET temp_directory='{sql_path(tmp)}'")
    con.execute("SET preserve_insertion_order=false")
    return con


def cmd_quick(a):
    rep = Report("LANL quick check")
    con = connect(a)
    found = {}

    for name in SCHEMAS:
        p = find_file(a.data_dir, name)
        if p is None:
            required = name in REQUIRED
            rep.add(f"G1 {name} file", "not found", FAIL if required else WARN,
                    "required" if required else "drop the questions that use it")
            continue
        found[name] = p
        size, expected = os.path.getsize(p), EXPECTED_GZ_BYTES[name]
        if p.endswith(".gz") and size < 0.85 * expected:
            rep.add(f"G1 {name} size", f"{human(size)}, expected ~{human(expected)}", WARN,
                    "possibly incomplete; check with gzip -t")
        else:
            rep.add(f"G1 {name} size", human(size), PASS)

    free = shutil.disk_usage(a.out or a.data_dir).free
    rep.add("G1 free disk", human(free), PASS if free >= 50e9 else WARN,
            "" if free >= 50e9 else "about 50 GB needed")

    if "redteam" in found:
        con.execute(f"""CREATE TEMP TABLE rt AS
            SELECT CAST(time AS BIGINT) AS time, "user", src_comp, dst_comp,
                   CAST((CAST(time AS BIGINT) - 1) // {DAY} + 1 AS INTEGER) AS day
            FROM {csv_src(found['redteam'], 'redteam')}""")
        n, dmin, dmax, users, srcs, dsts, user_days = con.execute("""
            SELECT count(*), min(day), max(day), count(DISTINCT "user"), count(DISTINCT src_comp),
                   count(DISTINCT dst_comp), count(DISTINCT ("user", day)) FROM rt""").fetchone()
        if n == 0:
            rep.add("D1 red team", "empty file", FAIL)
        else:
            rep.add("D1 red team size",
                    f"{n} events, {users} users, {dsts} targets, {user_days} user-days, days {dmin}-{dmax}",
                    PASS if user_days >= 20 else WARN,
                    "" if user_days >= 20 else "evaluate per event instead of per user-day")
            rep.add("D1 red team within --days", f"last day {dmax}, --days {a.days}",
                    PASS if dmax <= a.days else WARN, "" if dmax <= a.days else f"use --days {dmax} or more")
            rep.add("D7 red team source hosts", str(srcs), INFO)
            per_day = con.execute("SELECT day, count(*) FROM rt GROUP BY day ORDER BY day").fetchall()
            rep.note("Red team events per day: " + ", ".join(f"{d}: {k}" for d, k in per_day))

    if "auth" in found:
        t0 = time.time()
        con.execute(f"CREATE TEMP TABLE auth_s AS SELECT * FROM {csv_src(found['auth'], 'auth')} "
                    f"LIMIT {int(a.sample_rows)}")
        elapsed = max(time.time() - t0, 1e-6)
        rows = con.execute("SELECT count(*) FROM auth_s").fetchone()[0]
        whole = rows < a.sample_rows
        # x1.5 for the Parquet write on top of reading
        est_h = (elapsed if whole else AUTH_ROWS / (rows / elapsed)) * 1.5 / 3600
        st = PASS if est_h <= 8 else (WARN if est_h <= 24 else FAIL)
        rep.add("G1 auth conversion estimate", f"{rows:,} rows in {elapsed:.1f}s, ~{est_h:.1f} h total", st,
                "" if st == PASS else "run overnight")
        if not whole:
            rep.note(f"The sample is the first {rows:,} rows of day 1; rates below only catch format problems.")

        q_cols = ", ".join(f"avg(CASE WHEN {c} = '?' THEN 1.0 ELSE 0 END) AS {c}" for c in SCHEMAS["auth"])
        q_rates = con.execute(f"SELECT {q_cols} FROM auth_s").df().iloc[0]
        rep.add("D5 '?' in auth sample",
                ", ".join(f"{c}={v:.1%}" for c, v in q_rates.items() if v > 0) or "none", INFO)
        noise = con.execute(f"SELECT avg(CASE WHEN {NOISE_USER_SQL} THEN 1.0 ELSE 0 END) FROM auth_s").fetchone()[0]
        rep.add("D5 non-human accounts in sample", f"{noise:.1%}", INFO)
        top = con.execute("SELECT auth_type, count(*) FROM auth_s GROUP BY 1 ORDER BY 2 DESC LIMIT 6").fetchall()
        rep.note("Auth types in sample: " + ", ".join(f"{k}={v:,}" for k, v in top))
        bad_time = con.execute("SELECT count(*) FROM auth_s WHERE TRY_CAST(time AS BIGINT) IS NULL").fetchone()[0]
        rep.add("D5 unparseable time in sample", str(bad_time), PASS if bad_time == 0 else WARN)

    if "flows" in found:
        con.execute(f"CREATE TEMP TABLE flows_s AS SELECT * FROM {csv_src(found['flows'], 'flows')} "
                    f"LIMIT {int(min(a.sample_rows, 2_000_000))}")
        ports = con.execute(f"SELECT dst_port, count(*) FROM flows_s WHERE dst_port IN ({port_list()}) "
                            "GROUP BY 1 ORDER BY 2 DESC").fetchall()
        rep.add("D8 admin ports in flows sample", ", ".join(f"{p}: {n:,}" for p, n in ports) or "none", INFO)

    rep.write(os.path.join(a.out or a.data_dir, "report_quick.md"))


def cmd_convert(a):
    if not a.out:
        sys.exit("convert needs --out")
    rep = Report("LANL convert to Parquet")
    con = connect(a)
    targets = ["redteam", "dns", "flows", "auth"] + (["proc"] if a.with_proc else [])
    if a.only:
        targets = [t.strip() for t in a.only.split(",") if t.strip() in SCHEMAS]
    for name in targets:
        p = find_file(a.data_dir, name)
        if p is None:
            rep.add(f"convert {name}", "file not found", FAIL if name in REQUIRED else WARN)
            continue
        dest = os.path.join(a.out, name)
        if os.path.exists(dest):
            shutil.rmtree(dest)
        t0 = time.time()
        res = con.execute(f"""COPY (
              SELECT {SELECT_EXPR[name]}, CAST((TRY_CAST(time AS BIGINT) - 1) // {DAY} + 1 AS INTEGER) AS day
              FROM {csv_src(p, name, rejects=True)}
              WHERE TRY_CAST(time AS BIGINT) <= {a.days * DAY}
            ) TO '{sql_path(dest)}' (FORMAT parquet, PARTITION_BY (day), COMPRESSION zstd)""").fetchone()
        minutes = (time.time() - t0) / 60
        try:
            rejected = con.execute("SELECT count(*) FROM reject_errors").fetchone()[0]
            con.execute("DELETE FROM reject_errors")
        except duckdb.Error:
            rejected = 0
        rep.add(f"convert {name}",
                f"{res[0] if res else 0:,} rows, days 1-{a.days}, {human(dir_size(dest))}, {minutes:.1f} min",
                PASS if rejected == 0 else WARN, "" if rejected == 0 else f"{rejected:,} malformed rows dropped")
    rep.write(os.path.join(a.out, "report_convert.md"))


def acf(x, lag):
    x = np.asarray(x, dtype=float)
    if len(x) <= lag:
        return float("nan")
    x = x - x.mean()
    den = (x * x).sum()
    return float((x[:-lag] * x[lag:]).sum() / den) if den > 0 else float("nan")


def cmd_full(a):
    if not a.out:
        sys.exit("full needs --out")
    rep = Report("LANL full data checks")
    con = connect(a)
    have = {}
    for name in ["auth", "flows", "dns", "redteam", "proc"]:
        d = os.path.join(a.out, name)
        if os.path.isdir(d):
            con.execute(f"CREATE VIEW {name} AS SELECT * FROM "
                        f"read_parquet('{sql_path(d)}/*/*.parquet', hive_partitioning=true)")
            have[name] = d
    if "auth" not in have or "redteam" not in have:
        sys.exit("auth or redteam Parquet missing; run convert first")

    con.execute(f"""CREATE TEMP TABLE rt AS SELECT row_number() OVER () AS id, time, "user", src_comp, dst_comp, day
                    FROM redteam WHERE time <= {a.days * DAY}""")
    rt_days = [r[0] for r in con.execute("SELECT DISTINCT day FROM rt ORDER BY 1").fetchall()]
    n_rt = con.execute("SELECT count(*) FROM rt").fetchone()[0]
    rep.add("D1 red team in range", f"{n_rt} events on {len(rt_days)} days", PASS if n_rt else FAIL)

    cov = pd.DataFrame({"day": range(1, a.days + 1)})
    for name in ["auth", "flows", "dns"]:
        if name in have:
            counts = con.execute(f"SELECT day, count(*) AS {name} FROM {name} GROUP BY day").df()
            cov = cov.merge(counts, on="day", how="left")
    cov = cov.fillna(0).astype(int)
    cov_csv = os.path.join(a.out, "coverage_by_day.csv")
    cov.to_csv(cov_csv, index=False)
    for name in ["auth", "flows", "dns"]:
        if name not in cov:
            rep.add(f"D3 {name} coverage", "no data", FAIL if name in REQUIRED else WARN)
            continue
        present = cov.loc[cov[name] > 0, name]
        med = present.median() if len(present) else 0
        gaps = cov.loc[cov[name] < 0.2 * med, "day"].tolist() if med else cov["day"].tolist()
        gaps_rt = sorted(set(gaps) & set(rt_days))
        if not gaps:
            rep.add(f"D3 {name} coverage", "all days", PASS)
            continue
        msg = f"missing or sparse days {gaps}" + (f"; red team days among them: {gaps_rt}" if gaps_rt else "")
        if name == "auth":
            rep.add(f"D3 {name} coverage", msg, FAIL if gaps_rt else WARN,
                    "re-check the download" if gaps_rt else "exclude these days from the baseline")
        else:
            rep.add(f"D3 {name} coverage", msg, WARN,
                    "Q1 and Q5 only on covered days" if name == "flows" else "Q5 uses flows only on these days")
    rep.note(f"Rows per day: {cov_csv}")

    fields = ["src_user", "dst_user", "src_comp", "dst_comp", "auth_type", "logon_type", "outcome"]
    q_cols = ", ".join(f"avg(CASE WHEN {c} = '?' THEN 1.0 ELSE 0 END) AS {c}" for c in fields)
    q_rates = con.execute(f"SELECT {q_cols} FROM auth").df().iloc[0]
    rep.add("D5 '?' in auth", ", ".join(f"{c}={v:.2%}" for c, v in q_rates.items() if v > 0) or "none", INFO)
    total, noise, human_ok = con.execute(f"""SELECT count(*), count(*) FILTER (WHERE {NOISE_USER_SQL}),
            count(*) FILTER (WHERE {HUMAN_OK}) FROM auth""").fetchone()
    rep.add("D5 non-human accounts", f"{noise / total:.1%} of {total:,} events", INFO)
    rep.add("D5 human successful logons", f"{human_ok:,}", PASS if human_ok >= 1000 else FAIL)

    exact = con.execute("""WITH a AS (SELECT DISTINCT time, src_user, src_comp, dst_comp FROM auth
                                      WHERE time IN (SELECT time FROM rt))
        SELECT count(DISTINCT rt.id) FROM rt JOIN a ON rt.time = a.time AND rt."user" = a.src_user
          AND rt.src_comp = a.src_comp AND rt.dst_comp = a.dst_comp""").fetchone()[0]
    near = con.execute("""WITH a AS (SELECT time, src_user, src_comp, dst_comp FROM auth
                                     WHERE src_user IN (SELECT "user" FROM rt))
        SELECT count(DISTINCT rt.id) FROM rt JOIN a ON rt."user" = a.src_user AND rt.src_comp = a.src_comp
          AND rt.dst_comp = a.dst_comp AND abs(rt.time - a.time) <= 60""").fetchone()[0]
    rate = exact / n_rt if n_rt else 0
    rep.add("D2 red team matches auth", f"exact {exact}/{n_rt} ({rate:.0%}), within 60s {near}/{n_rt}",
            PASS if rate >= 0.95 else (WARN if near / max(n_rt, 1) >= 0.95 else FAIL),
            "" if rate >= 0.95 else "check the join columns and time offset")

    hourly = con.execute("SELECT (time - 1) // 3600 AS h, count(*) AS n FROM auth GROUP BY 1").df()
    hourly = hourly[hourly["h"].between(0, a.days * 24 - 1)]
    series = pd.Series(0, index=range(a.days * 24))
    series.loc[hourly["h"].astype(int)] = hourly["n"].values
    a24, a168 = acf(series.values, 24), acf(series.values, 168)
    rep.add("D4 autocorrelation of hourly auth", f"lag 24h {a24:.2f}, lag 7d {a168:.2f}",
            PASS if a24 >= 0.3 else WARN, "" if a24 >= 0.3 else "hour-of-day baseline is weak")
    busiest = series.groupby(series.index % 24).mean().sort_values(ascending=False).index[:6]
    rep.note("Busiest relative hours: " + ", ".join(map(str, busiest)))

    # New edge = first successful logon of a user to a host. Compare how often red team steps are new
    # edges with how often ordinary logons are, after a warm-up so early edges do not all count as new.
    warmup = a.warmup_days * DAY
    con.execute(f"""CREATE TEMP TABLE edge_first AS SELECT src_user, dst_comp, min(time) AS first_seen
                    FROM auth WHERE {HUMAN_OK} GROUP BY ALL""")
    n_ev = con.execute(f"SELECT count(*) FROM auth WHERE {HUMAN_OK} AND time > {warmup}").fetchone()[0]
    n_new = con.execute(f"SELECT count(*) FROM edge_first WHERE first_seen > {warmup}").fetchone()[0]
    base = n_new / n_ev if n_ev else float("nan")
    rt_n, rt_new, rt_unmatched = con.execute(f"""SELECT count(*), count(*) FILTER (WHERE e.first_seen = rt.time),
            count(*) FILTER (WHERE e.first_seen IS NULL)
        FROM rt LEFT JOIN edge_first e ON rt."user" = e.src_user AND rt.dst_comp = e.dst_comp
        WHERE rt.time > {warmup}""").fetchone()
    rt_rate = rt_new / rt_n if rt_n else float("nan")
    lift = rt_rate / base if base and base > 0 else float("nan")
    if rt_n < 20:
        st, act = WARN, "too few red team events after warm-up"
    elif lift >= 3:
        st, act = PASS, ""
    elif lift >= 1.5:
        st, act = WARN, "weak signal; add features"
    else:
        st, act = FAIL, "no signal; revisit the method"
    rep.add(f"D6 new-edge lift (warm-up {a.warmup_days} days)",
            f"red team {rt_new}/{rt_n} = {rt_rate:.1%}, normal {base:.2%}, lift {lift:.1f}"
            + (f", {rt_unmatched} unmatched" if rt_unmatched else ""), st, act)

    ntlm_rt, ntlm_all = con.execute(f"""WITH m AS (
            SELECT DISTINCT a.time, a.src_user, a.src_comp, a.dst_comp, a.auth_type
            FROM auth a JOIN rt ON rt.time = a.time AND rt."user" = a.src_user
             AND rt.src_comp = a.src_comp AND rt.dst_comp = a.dst_comp)
        SELECT (SELECT avg(CASE WHEN auth_type = 'NTLM' THEN 1.0 ELSE 0 END) FROM m),
               (SELECT avg(CASE WHEN auth_type = 'NTLM' THEN 1.0 ELSE 0 END) FROM auth WHERE {HUMAN_OK})""").fetchone()
    n_src = con.execute("SELECT count(DISTINCT src_comp) FROM rt").fetchone()[0]
    rep.add("D7 NTLM share", f"red team {ntlm_rt or 0:.0%}, normal {ntlm_all or 0:.0%}", INFO)
    rep.add("D7 red team source hosts", str(n_src), INFO)

    if "flows" in have:
        ports = con.execute(f"SELECT dst_port, count(*) FROM flows WHERE dst_port IN ({port_list()}) "
                            "GROUP BY 1 ORDER BY 2 DESC").fetchall()
        rep.add("D8 admin ports in flows", ", ".join(f"{p}: {n:,}" for p, n in ports) or "none", INFO)
        flow_days = cov.loc[cov["flows"] > 0, "day"].tolist() if "flows" in cov else []
        with_flow = con.execute("""WITH f AS (SELECT time, src_comp, dst_comp FROM flows
                                              WHERE src_comp IN (SELECT src_comp FROM rt))
            SELECT count(DISTINCT rt.id) FROM rt JOIN f ON f.src_comp = rt.src_comp AND f.dst_comp = rt.dst_comp
              AND abs(f.time - rt.time) <= 300""").fetchone()[0]
        n_cov = con.execute(f"SELECT count(*) FROM rt WHERE day IN ({','.join(map(str, flow_days)) or '-1'})"
                            ).fetchone()[0]
        frac = with_flow / n_cov if n_cov else 0
        rep.add("D9 red team events with a flow within 5 min", f"{with_flow}/{n_cov} ({frac:.0%})",
                PASS if frac >= 0.3 else WARN, "" if frac >= 0.3 else "Q5 becomes side information in V3")

    sizes = {k: dir_size(v) for k, v in have.items()}
    t0 = time.time()
    con.execute(f"""SELECT count(*) FROM (SELECT src_user, day, count(DISTINCT dst_comp) FROM auth
                    WHERE NOT {NOISE_USER_SQL} GROUP BY ALL)""").fetchone()
    qt = time.time() - t0
    rep.add("G1 Parquet size", ", ".join(f"{k}: {human(v)}" for k, v in sizes.items()), INFO)
    rep.add("G1 query time, distinct targets per user-day", f"{qt:.1f}s", PASS if qt <= 600 else WARN)

    failed = [r[0] for r in rep.rows if r[2] == FAIL]
    warned = [r[0] for r in rep.rows if r[2] == WARN]
    if failed:
        verdict = "NOT YET. Failed: " + "; ".join(failed)
    elif warned:
        verdict = "GO WITH CONDITIONS. Warnings: " + "; ".join(warned)
    else:
        verdict = "GO"
    rep.note("Data verdict: " + verdict)
    rep.write(os.path.join(a.out, "report_full.md"))


def main():
    ap = argparse.ArgumentParser(description="LANL dataset feasibility checks")
    ap.add_argument("step", choices=["quick", "convert", "full"])
    ap.add_argument("--data-dir", required=True, help="folder with auth.txt.gz, redteam.txt.gz, ...")
    ap.add_argument("--out", help="folder for Parquet and reports (required for convert and full)")
    ap.add_argument("--days", type=int, default=58, help="keep days 1..DAYS (default: all 58)")
    ap.add_argument("--warmup-days", type=int, default=3, help="days excluded from the D6 check")
    ap.add_argument("--sample-rows", type=int, default=5_000_000, help="rows sampled in quick")
    ap.add_argument("--with-proc", action="store_true", help="also convert proc")
    ap.add_argument("--only", help="convert only these sources, comma-separated")
    ap.add_argument("--threads", type=int)
    ap.add_argument("--memory-limit", help="e.g. 14GB")
    a = ap.parse_args()
    if a.out:
        os.makedirs(a.out, exist_ok=True)
    {"quick": cmd_quick, "convert": cmd_convert, "full": cmd_full}[a.step](a)


if __name__ == "__main__":
    main()
