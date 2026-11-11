"""CLI: vuln-agent owner/repo [--limit N]"""

import argparse

from . import db
from .github import GitHub
from .graph import remediate


def main() -> None:
    p = argparse.ArgumentParser(description="Remediate open security alerts for a GitHub repo")
    p.add_argument("repo", help="owner/name")
    p.add_argument("--limit", type=int, default=5, help="max alerts to process this run")
    args = p.parse_args()

    gh, conn = GitHub(args.repo), db.connect()
    alerts = [("dependabot", a) for a in gh.dependabot_alerts()]
    alerts += [("code_scanning", a) for a in gh.code_scanning_alerts()]

    done = 0
    for kind, alert in alerts:
        if done >= args.limit:
            break
        if db.already_handled(conn, args.repo, kind, alert["number"]):
            continue
        print(f"[{kind} #{alert['number']}] remediating...")
        try:
            result = remediate(args.repo, kind, alert, conn)
            print(f"  -> {result['status']} {result.get('pr_url') or result.get('detail') or ''}")
        except Exception as exc:
            print(f"  -> error: {exc}")
        done += 1


if __name__ == "__main__":
    main()
