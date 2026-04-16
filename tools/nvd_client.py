"""
tools/nvd_client.py
-------------------
Queries the NIST National Vulnerability Database (NVD) REST API
to fetch CVEs for a given service name and version.
Used exclusively by the IP range analyzer agent.
"""

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

# ── constants ──────────────────────────────────────────────────────────────
NVD_BASE_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESULTS   = 10       # CVEs returned per service query
CVSS_MIN      = 5.0      # ignore low-severity CVEs below this score
REQUEST_DELAY = 0.6      # seconds between requests (NVD rate limit: 5 req/30s without key)


# ── helpers ────────────────────────────────────────────────────────────────
def _get_headers() -> dict:
    """Add API key header if available — raises rate limit from 5 to 50 req/30s."""
    api_key = os.getenv("NVD_API_KEY", "")
    if api_key:
        return {"apiKey": api_key}
    return {}


def _parse_cvss(cve_item: dict) -> float:
    """
    Extract the highest CVSS score from a CVE item.
    Tries CVSS v3.1 first, then v3.0, then v2.
    Returns 0.0 if no score is found.
    """
    try:
        metrics = cve_item.get("metrics", {})

        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics:
                return float(
                    metrics[key][0]["cvssData"]["baseScore"]
                )

        if "cvssMetricV2" in metrics:
            return float(
                metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            )
    except (KeyError, IndexError, TypeError, ValueError):
        pass

    return 0.0


def _parse_description(cve_item: dict) -> str:
    """Extract the English description from a CVE item."""
    try:
        for desc in cve_item["descriptions"]:
            if desc.get("lang") == "en":
                return desc.get("value", "No description available.")
    except (KeyError, TypeError):
        pass
    return "No description available."


# ── main public function ───────────────────────────────────────────────────
def fetch_cves(service_name: str, version: str = "") -> list[dict]:
    """
    Query the NVD API for CVEs matching a service name and optional version.

    Parameters
    ----------
    service_name : str
        Name of the service/software, e.g. "openssh", "apache httpd", "nginx"
    version : str
        Version string, e.g. "7.4", "2.4.51". Leave empty to search by name only.

    Returns
    -------
    list[dict]
        List of CVE dicts, each containing:
        {
            "cve_id":          str,   e.g. "CVE-2023-38408"
            "cvss_score":      float, e.g. 9.8
            "severity":        str,   e.g. "CRITICAL"
            "description":     str,
            "affected_service": str,  e.g. "openssh 7.4"
            "url":             str,   NVD detail page URL
        }
        Sorted by CVSS score descending.
        Returns empty list on any error (agent continues gracefully).
    """
    # build search keyword
    keyword = f"{service_name} {version}".strip()

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": MAX_RESULTS,
        "startIndex":     0,
    }

    try:
        time.sleep(REQUEST_DELAY)  # respect rate limit

        response = requests.get(
            NVD_BASE_URL,
            params=params,
            headers=_get_headers(),
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()

    except requests.exceptions.Timeout:
        print(f"[nvd_client] Timeout querying NVD for '{keyword}'")
        return []
    except requests.exceptions.HTTPError as e:
        print(f"[nvd_client] HTTP error for '{keyword}': {e}")
        return []
    except Exception as e:
        print(f"[nvd_client] Unexpected error for '{keyword}': {e}")
        return []

    # parse results
    results = []
    for item in data.get("vulnerabilities", []):
        cve_item = item.get("cve", {})
        cve_id   = cve_item.get("id", "UNKNOWN")
        score    = _parse_cvss(cve_item)
        desc     = _parse_description(cve_item)

        # skip low-severity CVEs
        if score < CVSS_MIN:
            continue

        # determine severity label
        if score >= 9.0:
            severity = "CRITICAL"
        elif score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        results.append({
            "cve_id":           cve_id,
            "cvss_score":       score,
            "severity":         severity,
            "description":      desc,
            "affected_service": keyword,
            "url":              f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    # sort by CVSS score descending (most critical first)
    results.sort(key=lambda x: x["cvss_score"], reverse=True)
    return results


def fetch_cves_for_hosts(scan_results: list[dict]) -> list[dict]:
    """
    Convenience wrapper — runs fetch_cves() for every service
    found across all scanned hosts.

    Parameters
    ----------
    scan_results : list[dict]
        Output from the Nmap scanner, each dict has:
        { "ip": str, "open_ports": list[str], "services": list[str] }

    Returns
    -------
    list[dict]
        Combined, deduplicated CVE list across all hosts.
    """
    all_cves  = []
    seen_ids  = set()

    for host in scan_results:
        for service in host.get("services", []):
            # service format: "openssh 8.2" or just "apache"
            parts   = service.strip().split(" ", 1)
            name    = parts[0]
            version = parts[1] if len(parts) > 1 else ""

            cves = fetch_cves(name, version)

            for cve in cves:
                if cve["cve_id"] not in seen_ids:
                    seen_ids.add(cve["cve_id"])
                    all_cves.append(cve)

    all_cves.sort(key=lambda x: x["cvss_score"], reverse=True)
    return all_cves


# ── quick self-test ────────────────────────────────────────────────────────
if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    console = Console()
    console.print("\n[bold cyan]Testing nvd_client.py...[/bold cyan]")
    console.print("[dim]Querying NVD API for OpenSSH CVEs — this takes ~2 seconds[/dim]\n")

    cves = fetch_cves("openssh", "8.2")

    if not cves:
        console.print(Panel(
            "No CVEs returned.\n"
            "Either the NVD API is down, your NVD_API_KEY is invalid,\n"
            "or no CVEs matched. Check your .env file.",
            title="[yellow]No results[/yellow]",
            border_style="yellow"
        ))
    else:
        table = Table(show_header=True, header_style="bold cyan", show_lines=True)
        table.add_column("CVE ID",       style="white",  width=18)
        table.add_column("CVSS",         style="bold",   width=6,  justify="right")
        table.add_column("Severity",     width=10)
        table.add_column("Description",  width=55)

        for cve in cves:
            sev   = cve["severity"]
            color = {"CRITICAL": "red", "HIGH": "orange3",
                     "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")
            table.add_row(
                cve["cve_id"],
                str(cve["cvss_score"]),
                f"[{color}]{sev}[/{color}]",
                cve["description"][:120] + "...",
            )

        console.print(table)
        console.print(f"\n[bold green]nvd_client.py OK — {len(cves)} CVEs returned.[/bold green]\n")