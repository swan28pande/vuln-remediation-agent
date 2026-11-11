"""LangGraph workflow: one run remediates one alert.

enrich -> draft -> push_branch -> wait_for_ci -> open_pr
            |                          |
            +-> (no fix) END           +-> (CI failed) END
"""

import time
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from . import db, osv
from .config import settings
from .github import GitHub
from .llm import Fix, draft_fix


class State(TypedDict, total=False):
    repo: str
    kind: str                  # 'dependabot' | 'code_scanning'
    alert: dict[str, Any]
    vuln_id: str | None
    osv: dict | None
    files: dict[str, str]
    base: str
    fix: Fix
    branch: str
    head_sha: str
    ci_passed: bool
    pr_url: str
    status: str
    detail: str


def _alert_number(state: State) -> int:
    return state["alert"]["number"]


def enrich(state: State) -> State:
    gh, alert = GitHub(state["repo"]), state["alert"]
    base = gh.default_branch()
    if state["kind"] == "dependabot":
        adv = alert["security_advisory"]
        vuln_id = adv.get("ghsa_id") or adv.get("cve_id")
        path = alert["dependency"]["manifest_path"]
    else:
        vuln_id = alert["rule"]["id"]  # e.g. CodeQL rule; not an OSV id
        path = alert["most_recent_instance"]["location"]["path"]
    record = osv.get_vuln(vuln_id) if state["kind"] == "dependabot" and vuln_id else None
    text, _ = gh.read_file(path, base)
    return {"base": base, "vuln_id": vuln_id, "osv": record, "files": {path: text}}


def draft(state: State) -> State:
    fix = draft_fix(state["alert"], state.get("osv"), state["files"])
    if fix.fix_type == "none" or not fix.edits:
        return {"fix": fix, "status": "skipped", "detail": fix.rationale}
    return {"fix": fix, "status": "drafted"}


def push_branch(state: State) -> State:
    gh, fix = GitHub(state["repo"]), state["fix"]
    branch = f"vuln-agent/{state['kind']}-{_alert_number(state)}"
    gh.create_branch(branch, state["base"])
    sha = ""
    for edit in fix.edits:
        sha = gh.write_file(edit.path, edit.new_content, branch, f"fix: {fix.summary}")
    return {"branch": branch, "head_sha": sha}


def wait_for_ci(state: State) -> State:
    """Poll check runs on the fix commit until they all finish or we time out."""
    gh = GitHub(state["repo"])
    deadline = time.time() + settings.check_timeout_s
    while time.time() < deadline:
        runs = gh.check_runs(state["head_sha"])
        if runs and all(r["status"] == "completed" for r in runs):
            ok = all(r["conclusion"] in ("success", "neutral", "skipped") for r in runs)
            failed = [r["name"] for r in runs if r["conclusion"] not in ("success", "neutral", "skipped")]
            return {
                "ci_passed": ok,
                "status": "drafted" if ok else "ci_failed",
                "detail": "" if ok else f"failed checks: {', '.join(failed)}",
            }
        time.sleep(settings.check_poll_s)
    return {"ci_passed": False, "status": "ci_failed", "detail": "timed out waiting for checks"}


def open_pr(state: State) -> State:
    gh, fix = GitHub(state["repo"]), state["fix"]
    body = (
        f"Automated remediation for {state['kind']} alert #{_alert_number(state)}"
        f" ({state.get('vuln_id') or 'n/a'}).\n\n{fix.rationale}\n\nCI passed on `{state['head_sha'][:7]}`."
    )
    url = gh.open_pr(state["branch"], state["base"], fix.summary, body)
    return {"pr_url": url, "status": "pr_opened"}


def build_graph():
    g = StateGraph(State)
    for name, fn in [("enrich", enrich), ("draft", draft), ("push_branch", push_branch),
                     ("wait_for_ci", wait_for_ci), ("open_pr", open_pr)]:
        g.add_node(name, fn)
    g.add_edge(START, "enrich")
    g.add_edge("enrich", "draft")
    g.add_conditional_edges("draft", lambda s: END if s["status"] == "skipped" else "push_branch")
    g.add_edge("push_branch", "wait_for_ci")
    g.add_conditional_edges("wait_for_ci", lambda s: "open_pr" if s["ci_passed"] else END)
    g.add_edge("open_pr", END)
    return g.compile()


def remediate(repo: str, kind: str, alert: dict, conn) -> State:
    number = alert["number"]
    try:
        result = build_graph().invoke({"repo": repo, "kind": kind, "alert": alert})
    except Exception as exc:  # record and move on to the next alert
        db.record(conn, repo, kind, number, "error", detail=str(exc))
        raise
    db.record(
        conn, repo, kind, number, result["status"],
        vuln_id=result.get("vuln_id"), branch=result.get("branch"),
        pr_url=result.get("pr_url"), detail=result.get("detail"),
    )
    return result
