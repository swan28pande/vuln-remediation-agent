"""Thin GitHub REST client covering only what the agent needs."""

import base64

import httpx

from .config import settings


class GitHub:
    def __init__(self, repo: str, token: str = settings.github_token):
        self.repo = repo
        self.http = httpx.Client(
            base_url=f"https://api.github.com/repos/{repo}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30,
        )

    def _get(self, path: str, **params):
        r = self.http.get(path, params=params)
        r.raise_for_status()
        return r.json()

    # --- alerts -----------------------------------------------------------
    def dependabot_alerts(self) -> list[dict]:
        return self._get("/dependabot/alerts", state="open", per_page=100)

    def code_scanning_alerts(self) -> list[dict]:
        r = self.http.get("/code-scanning/alerts", params={"state": "open", "per_page": 100})
        if r.status_code == 404:  # code scanning not enabled
            return []
        r.raise_for_status()
        return r.json()

    # --- repo contents ----------------------------------------------------
    def default_branch(self) -> str:
        return self._get("")["default_branch"]

    def read_file(self, path: str, ref: str) -> tuple[str, str]:
        """Return (text, blob_sha)."""
        data = self._get(f"/contents/{path}", ref=ref)
        return base64.b64decode(data["content"]).decode(), data["sha"]

    def create_branch(self, name: str, from_branch: str) -> None:
        sha = self._get(f"/git/ref/heads/{from_branch}")["object"]["sha"]
        r = self.http.post("/git/refs", json={"ref": f"refs/heads/{name}", "sha": sha})
        if r.status_code == 422:  # branch exists from an earlier attempt: reset it
            r = self.http.patch(f"/git/refs/heads/{name}", json={"sha": sha, "force": True})
        r.raise_for_status()

    def write_file(self, path: str, content: str, branch: str, message: str) -> str:
        """Commit a file update on `branch`; returns the new commit sha."""
        _, blob_sha = self.read_file(path, branch)
        r = self.http.put(
            f"/contents/{path}",
            json={
                "message": message,
                "content": base64.b64encode(content.encode()).decode(),
                "sha": blob_sha,
                "branch": branch,
            },
        )
        r.raise_for_status()
        return r.json()["commit"]["sha"]

    # --- CI + PRs ---------------------------------------------------------
    def check_runs(self, sha: str) -> list[dict]:
        return self._get(f"/commits/{sha}/check-runs", per_page=100)["check_runs"]

    def open_pr(self, head: str, base: str, title: str, body: str) -> str:
        r = self.http.post(
            "/pulls", json={"head": head, "base": base, "title": title, "body": body}
        )
        r.raise_for_status()
        return r.json()["html_url"]
