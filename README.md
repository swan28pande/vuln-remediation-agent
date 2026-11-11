# AI Vulnerability Remediation Agent

An LLM agent that reads Dependabot and code-scanning alerts for a GitHub repository, looks them up in the [OSV](https://osv.dev) database, drafts a fix (version bump or code patch), pushes it to a branch, and opens a pull request once CI passes.

**Stack:** Python · LangGraph · GitHub REST API · OSV API · PostgreSQL · Claude

## How it works

Each alert runs through a small LangGraph state machine:

```
enrich ──► draft ──► push_branch ──► wait_for_ci ──► open_pr
             │                           │
             └─► no safe fix: stop       └─► CI failed: stop
```

| Node | What it does |
|---|---|
| `enrich` | Loads the affected file (manifest or flagged source file) and the OSV record for the advisory |
| `draft` | Asks Claude for the smallest fix, returned as structured JSON (full new file contents) |
| `push_branch` | Creates `vuln-agent/<kind>-<n>` and commits the edits through the GitHub API |
| `wait_for_ci` | Polls check runs on the fix commit until they all complete |
| `open_pr` | Opens the PR only if every check succeeded |

Every outcome (`pr_opened`, `ci_failed`, `skipped`, `error`) is stored in the `remediations` table in Postgres, so alerts that already have a PR or were skipped aren't processed again.

## Quick start

```bash
docker compose up -d                 # local Postgres
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env                 # fill in GITHUB_TOKEN and ANTHROPIC_API_KEY
vuln-agent owner/repo --limit 3
```

The GitHub token needs `repo` and `security_events` access. The schema is created on first run.

## Notes and limitations

- CI has to run on **push** to the fix branch, since the PR doesn't exist yet when the agent waits for checks.
- Fixes replace whole files, so the skeleton works best on small manifests and source files. Lockfiles are not regenerated.
- The model defaults to `claude-opus-5-5` (`ANTHROPIC_MODEL` overrides it). Server-side refusal fallback is enabled.
- This is a starting skeleton. It has no tests, no retries, and handles one alert at a time.

## Layout

```
src/vuln_agent/
  main.py     CLI entry point
  graph.py    LangGraph workflow
  github.py   GitHub REST client
  osv.py      OSV lookups
  llm.py      Claude fix drafting
  db.py       Postgres persistence
  config.py   Settings from env
```
