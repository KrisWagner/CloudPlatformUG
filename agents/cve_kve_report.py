#!/usr/bin/env python3
"""Daily critical CVE/KVE email report agent.

Fetches critical CVEs from NVD and Kubernetes security advisories (KVEs)
published in the last N days, then emails an HTML report.

Required environment variables:
    SMTP_HOST      SMTP server hostname
    SMTP_USER      SMTP username / login
    SMTP_PASS      SMTP password

Optional environment variables:
    SMTP_PORT         SMTP port (default: 587)
    SMTP_FROM         From address (default: SMTP_USER)
    REPORT_TO_EMAIL   Recipient (default: kristopher.wagner@icloud.com)
    NVD_API_KEY       NVD API key for higher rate limits
    GITHUB_TOKEN      GitHub token for Advisory API
    DAYS_BACK         Days to look back (default: 1)
"""

import json
import os
import smtplib
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_ADVISORY_API = "https://api.github.com/advisories"

# Kubernetes-ecosystem package prefixes / names tracked for KVEs
KUBERNETES_PKG_PREFIXES = (
    "k8s.io/",
    "sigs.k8s.io/",
    "github.com/kubernetes/",
    "github.com/containerd/",
    "github.com/opencontainers/runc",
    "helm.sh/helm",
    "github.com/argoproj/argo",
    "istio.io/",
    "github.com/cilium/",
    "github.com/projectcalico/",
    "github.com/cri-o/",
)

KUBERNETES_KEYWORDS = frozenset({
    "kubernetes", "kubectl", "kubelet", "kube-apiserver", "kube-proxy",
    "kube-scheduler", "kube-controller", "etcd", "containerd", "cri-o",
    "k8s.io", "helm", "runc", "cilium", "calico", "istio", "argo cd",
    "argocd", "kubeadm", "minikube", "eks", "gke", "aks", "openshift",
})


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http_get(url: str, headers: dict, retries: int = 4) -> dict | list:
    req = urllib.request.Request(url, headers=headers)
    delay = 2
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 404, 422):
                raise
            if attempt == retries - 1:
                raise
        except Exception:
            if attempt == retries - 1:
                raise
        time.sleep(delay)
        delay *= 2
    raise RuntimeError("Unreachable")


# ---------------------------------------------------------------------------
# Data fetchers
# ---------------------------------------------------------------------------

def fetch_critical_cves(start: datetime, end: datetime) -> list[dict]:
    """Return critical CVEs from NVD published in [start, end]."""
    headers = {"User-Agent": "CloudPlatformUG-VulnReport/1.0"}
    if api_key := os.getenv("NVD_API_KEY"):
        headers["apiKey"] = api_key

    results: list[dict] = []
    start_index = 0
    page_size = 2000

    while True:
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.999"),
            "cvssV3Severity": "CRITICAL",
            "startIndex": str(start_index),
            "resultsPerPage": str(page_size),
        }
        url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
        try:
            data = _http_get(url, headers)
        except Exception as exc:
            print(f"  Warning: NVD API error — {exc}")
            break

        vulns = data.get("vulnerabilities", [])
        results.extend(vulns)

        total = data.get("totalResults", 0)
        start_index += page_size
        if start_index >= total:
            break

        # NVD rate-limit: ~5 req/s without key, 50/s with key
        time.sleep(0.6 if headers.get("apiKey") else 6)

    return results


def fetch_critical_kves(start: datetime) -> list[dict]:
    """Return critical Kubernetes-related advisories from GitHub GHSA."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "CloudPlatformUG-VulnReport/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"

    kves: list[dict] = []
    seen: set[str] = set()

    for ecosystem in ("go", "actions", "pip"):
        params = {
            "ecosystem": ecosystem,
            "severity": "critical",
            "per_page": "100",
            "type": "reviewed",
        }
        url = f"{GITHUB_ADVISORY_API}?{urllib.parse.urlencode(params)}"
        try:
            advisories = _http_get(url, headers)
        except Exception as exc:
            print(f"  Warning: GitHub Advisory API error ({ecosystem}) — {exc}")
            continue

        for adv in advisories:
            ghsa_id = adv.get("ghsa_id", "")
            if ghsa_id in seen:
                continue

            published_at = adv.get("published_at", "")
            if published_at:
                pub_dt = datetime.strptime(published_at[:19], "%Y-%m-%dT%H:%M:%S")
                pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                if pub_dt < start:
                    continue

            if _is_kubernetes_advisory(adv):
                seen.add(ghsa_id)
                kves.append(adv)

    return kves


def _is_kubernetes_advisory(adv: dict) -> bool:
    for vuln in adv.get("vulnerabilities", []):
        pkg_name = (vuln.get("package") or {}).get("name", "").lower()
        if any(pkg_name.startswith(pfx) for pfx in KUBERNETES_PKG_PREFIXES):
            return True

    text = f"{adv.get('summary', '')} {adv.get('description', '')}".lower()
    return any(kw in text for kw in KUBERNETES_KEYWORDS)


# ---------------------------------------------------------------------------
# HTML builders
# ---------------------------------------------------------------------------

_HEADER_CELL = "padding:10px 12px;text-align:left;background:#1a252f;color:#fff;font-size:13px"


def _cve_row(vuln: dict) -> str:
    cve_data = vuln.get("cve", {})
    cve_id = cve_data.get("id", "N/A")

    descs = cve_data.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "No description available")
    if len(desc) > 380:
        desc = desc[:377] + "…"

    score, vector = "N/A", ""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics := cve_data.get("metrics", {}).get(key):
            cvss = metrics[0].get("cvssData", {})
            score = cvss.get("baseScore", "N/A")
            vector = cvss.get("vectorString", "")
            break

    refs = cve_data.get("references", [])
    href = refs[0]["url"] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    return (
        f'<tr><td style="padding:10px 12px;border-bottom:1px solid #eee;font-weight:bold;white-space:nowrap;vertical-align:top">'
        f'<a href="{href}" style="color:#c0392b;text-decoration:none">{cve_id}</a></td>'
        f'<td style="padding:10px 12px;border-bottom:1px solid #eee;font-size:13px;vertical-align:top">{desc}</td>'
        f'<td style="padding:10px 12px;border-bottom:1px solid #eee;text-align:center;font-weight:bold;color:#c0392b;vertical-align:top">{score}</td>'
        f'<td style="padding:10px 12px;border-bottom:1px solid #eee;font-size:11px;color:#888;vertical-align:top">{vector}</td></tr>'
    )


def _kve_row(adv: dict) -> str:
    ghsa_id = adv.get("ghsa_id", "N/A")
    summary = adv.get("summary", "No summary")
    if len(summary) > 260:
        summary = summary[:257] + "…"

    cvss_data = adv.get("cvss") or {}
    score = cvss_data.get("score", "N/A")
    href = adv.get("html_url", f"https://github.com/advisories/{ghsa_id}")

    cve_ids = [i["value"] for i in adv.get("identifiers", []) if i.get("type") == "CVE"]
    cve_label = f'<br><small style="color:#888">{", ".join(cve_ids)}</small>' if cve_ids else ""

    pkgs = [
        (v.get("package") or {}).get("name", "")
        for v in adv.get("vulnerabilities", [])
        if (v.get("package") or {}).get("name")
    ]
    pkg_text = ", ".join(pkgs[:4]) + ("…" if len(pkgs) > 4 else "")

    return (
        f'<tr><td style="padding:10px 12px;border-bottom:1px solid #eee;font-weight:bold;white-space:nowrap;vertical-align:top">'
        f'<a href="{href}" style="color:#2980b9;text-decoration:none">{ghsa_id}</a>{cve_label}</td>'
        f'<td style="padding:10px 12px;border-bottom:1px solid #eee;font-size:13px;vertical-align:top">{summary}</td>'
        f'<td style="padding:10px 12px;border-bottom:1px solid #eee;text-align:center;font-weight:bold;color:#c0392b;vertical-align:top">{score}</td>'
        f'<td style="padding:10px 12px;border-bottom:1px solid #eee;font-size:12px;color:#555;vertical-align:top">{pkg_text}</td></tr>'
    )


def build_email_html(cves: list, kves: list, report_date: str) -> str:
    empty_cve = '<tr><td colspan="4" style="padding:16px;text-align:center;color:#999">No new critical CVEs in this period.</td></tr>'
    empty_kve = '<tr><td colspan="4" style="padding:16px;text-align:center;color:#999">No new critical Kubernetes advisories in this period.</td></tr>'

    cve_rows = "".join(_cve_row(v) for v in cves) or empty_cve
    kve_rows = "".join(_kve_row(a) for a in kves) or empty_kve

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="font-family:Arial,Helvetica,sans-serif;max-width:980px;margin:0 auto;padding:20px;background:#f0f2f5;color:#333">
<div style="background:#fff;border-radius:8px;padding:28px 32px;box-shadow:0 2px 10px rgba(0,0,0,.08)">

  <h1 style="margin:0 0 6px;color:#c0392b;font-size:22px">
    &#128274; Daily Critical Vulnerability Report
  </h1>
  <p style="margin:0 0 28px;color:#999;font-size:13px">
    Generated: <strong>{report_date} UTC</strong>&emsp;|&emsp;Severity: <strong>CRITICAL</strong>
  </p>

  <h2 style="color:#2c3e50;font-size:17px;border-left:4px solid #c0392b;padding-left:10px;margin:0 0 4px">
    CVEs &mdash; {len(cves)} new critical
  </h2>
  <p style="font-size:12px;color:#aaa;margin:0 0 12px">
    Source: <a href="https://nvd.nist.gov" style="color:#aaa">NVD / NIST National Vulnerability Database</a>
  </p>
  <div style="overflow-x:auto">
  <table width="100%" style="border-collapse:collapse;font-size:14px">
    <thead><tr>
      <th style="{_HEADER_CELL};min-width:130px">CVE ID</th>
      <th style="{_HEADER_CELL}">Description</th>
      <th style="{_HEADER_CELL};text-align:center;min-width:60px">Score</th>
      <th style="{_HEADER_CELL};min-width:120px">CVSS Vector</th>
    </tr></thead>
    <tbody>{cve_rows}</tbody>
  </table>
  </div>

  <h2 style="color:#2c3e50;font-size:17px;border-left:4px solid #2980b9;padding-left:10px;margin:36px 0 4px">
    Kubernetes Vulnerabilities (KVEs) &mdash; {len(kves)} new critical
  </h2>
  <p style="font-size:12px;color:#aaa;margin:0 0 12px">
    Source: <a href="https://github.com/advisories" style="color:#aaa">GitHub Security Advisories</a>
    &mdash; k8s.io, containerd, runc, Helm, Argo CD, Istio, Cilium, Calico&hellip;
  </p>
  <div style="overflow-x:auto">
  <table width="100%" style="border-collapse:collapse;font-size:14px">
    <thead><tr>
      <th style="{_HEADER_CELL};min-width:160px">Advisory / CVE</th>
      <th style="{_HEADER_CELL}">Summary</th>
      <th style="{_HEADER_CELL};text-align:center;min-width:60px">Score</th>
      <th style="{_HEADER_CELL};min-width:200px">Packages</th>
    </tr></thead>
    <tbody>{kve_rows}</tbody>
  </table>
  </div>

  <p style="margin-top:36px;font-size:11px;color:#ccc;border-top:1px solid #eee;padding-top:14px">
    CloudPlatformUG Daily Vulnerability Agent &middot;
    <a href="https://nvd.nist.gov" style="color:#ccc">NVD</a> &middot;
    <a href="https://github.com/advisories" style="color:#ccc">GitHub Advisories</a>
  </p>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Email sender
# ---------------------------------------------------------------------------

def send_email(subject: str, html_body: str, to_addr: str) -> None:
    smtp_host = os.environ["SMTP_HOST"]
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.environ["SMTP_USER"]
    smtp_pass = os.environ["SMTP_PASS"]
    from_addr = os.getenv("SMTP_FROM", smtp_user)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(smtp_user, smtp_pass)
        server.sendmail(from_addr, [to_addr], msg.as_string())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    days_back = int(os.getenv("DAYS_BACK", "1"))
    to_email = os.getenv("REPORT_TO_EMAIL", "kristopher.wagner@icloud.com")

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days_back)
    report_date = now.strftime("%Y-%m-%d %H:%M")

    print(f"[{report_date} UTC] Fetching critical CVEs (last {days_back}d)…")
    cves = fetch_critical_cves(start, now)
    print(f"  {len(cves)} critical CVE(s) found")

    print("Fetching critical Kubernetes advisories (KVEs)…")
    kves = fetch_critical_kves(start)
    print(f"  {len(kves)} critical KVE(s) found")

    subject = (
        f"[CRITICAL] {len(cves)} CVE(s) · {len(kves)} KVE(s) — "
        f"{now.strftime('%b %d, %Y')}"
    )
    html_body = build_email_html(cves, kves, report_date)

    print(f"Sending report to {to_email}…")
    send_email(subject, html_body, to_email)
    print("Done.")


if __name__ == "__main__":
    main()
