# Detecting lateral movement in the LANL dataset

This repo holds the data pipeline, analysis and dashboard code. For now it contains the scripts
that check whether the LANL dataset fits the project, and the reports from running them on the full data.

How the team works on the repo (setup, branches, commits) is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Data

[Comprehensive, Multi-Source Cyber-Security Events](https://csr.lanl.gov/data/cyber1/) from Los Alamos
National Laboratory: 58 days of auth, flows, DNS, process and red team logs, released under CC0.
Request access through the form on that page. The data is not stored in this repo.

## Setup

Python 3.11 or newer (pandas 3 and NumPy 2.4 need it). Versions are pinned to the ones used for the reports.

```
conda create -n lanl python=3.11
conda activate lanl
pip install -r requirements.txt
```

## Running the checks

`<gz>` is the folder with the downloaded `.txt.gz` files, `<out>` is where Parquet files and reports go
(about 10 GB). Add `--memory-limit 14GB` on machines with 16 GB of RAM.

```
python checks/lanl_check.py quick   --data-dir <gz> --out <out>
python checks/lanl_check.py convert --data-dir <gz> --out <out>
python checks/lanl_check.py full    --data-dir <gz> --out <out>
python checks/lanl_probe.py       --out <out>
python checks/lanl_followup.py    --out <out>
python checks/lanl_lead_check.py  --out <out>
```

| Script | What it checks | Writes |
|---|---|---|
| `lanl_check.py quick` | Files present and readable, row sample | `report_quick.md` |
| `lanl_check.py convert` | Converts `.txt.gz` to Parquet partitioned by day | `auth/`, `flows/`, `dns/`, `redteam/`, `report_convert.md` |
| `lanl_check.py full` | Coverage per day, label match, noise accounts, daily rhythm, new-edge signal, NTLM bias, ports | `report_full.md`, `coverage_by_day.csv` |
| `lanl_probe.py` | Red team edges, new edges per day, flows and DNS around red team steps, SMB/RPC fan-out | `report_probe.md`, `new_edges_by_day.csv` |
| `lanl_followup.py` | What `?` means per event type; how much of the main attacker host's activity the labels cover | `report_followup.md`, `attacker_host_by_day.csv` |
| `lanl_lead_check.py` | Per-day timing of one source host, to rule out day-boundary artifacts | prints to the console |

`convert` takes about 17 minutes on a laptop. Add a source later with `convert --only proc`.

## Layout

```
checks/      data checks run before the project started (done)
pipeline/    cleaning, integration, loading into HDFS
analysis/    features, scoring, spread graph, evaluation
dashboard/   Streamlit app, one module per view
infra/       docker-compose for the HDFS cluster
docs/        data dictionary, glossary
reports/     outputs worth keeping, never raw data
```

Folders other than `checks/` and `reports/` are created when their first file goes in.

## Conventions

- Data paths come from the `--out` argument, or the `LANL_OUT` environment variable in new code. Never hard-code a local path.
- Never commit data. Parquet and `.gz` files are ignored, but check `git status` before each commit.
- One branch per task, named `<your-name>/<task>` (for example `yourname/cleaning`), merged into `main` through a pull request.
- Commit messages in English, imperative mood: "Add cleaning rules for machine accounts".

## Reports

`reports/data_check/` has the outputs of the run on 19–20 Nov 2026 over all 58 days.
The findings are summarised as rounds 1–9 of the iteration log in the project plan.