"""OSV.dev lookups (https://google.github.io/osv.dev/api/)."""

import httpx

OSV_API = "https://api.osv.dev/v1"


def get_vuln(vuln_id: str) -> dict | None:
    """Fetch a record by GHSA/CVE/OSV id. Returns None if OSV doesn't know it."""
    r = httpx.get(f"{OSV_API}/vulns/{vuln_id}", timeout=30)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def fixed_versions(record: dict, package: str) -> list[str]:
    """Collect every 'fixed' version OSV lists for `package`."""
    out: list[str] = []
    for affected in record.get("affected", []):
        if affected.get("package", {}).get("name") != package:
            continue
        for rng in affected.get("ranges", []):
            out += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return out
