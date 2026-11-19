# Contributing

## Setup

```
git clone git@github.com:Nov17th/lanl-lateral-movement.git
```

Set up the environment as in the README. Keep the LANL data outside the repo folder: either the converted
Parquet folder from a teammate (about 9 GB) or your own run of `checks/lanl_check.py convert`. Set the
`LANL_OUT` environment variable to that folder.

## Workflow

- One branch per task, named `<your-name>/<task>`, branched from an up-to-date `main`.
- Changes reach `main` only through a pull request reviewed by another member.
- Do not amend or force-push commits that are already on `main`; fix mistakes with a new commit.

## Rules

- Never commit data: no Parquet, no `.gz`, nothing copied from LANL. Check `git status` before committing.
- Never commit local paths, passwords or tokens. Code reads data paths from `--out` or `LANL_OUT`.
- Put code in the folder for its stage (see Layout in the README).

## Commit messages

In English. The first line is in the imperative ("Add", "Fix", "Remove"), under about 60 characters, and says
what changed. If more is needed, add a blank line and a short body saying what and why:

```
Add cleaning rules for auth

- Drop machine accounts (names ending in $) and SYSTEM
- Mark "?" in auth_type and logon_type as N/A by event type
```