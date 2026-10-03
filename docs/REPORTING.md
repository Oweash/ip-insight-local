# Reporting and interpretation

## What the ZIP contains

| File | Purpose |
|---|---|
| `report.html` | Formatted tables and interpretation notes; print to PDF. |
| `report.docx` | Editable Word document with semantic headings. |
| `report.txt` | Plain text case narrative. |
| `report.json` | Complete machine-readable snapshot, including notes and imported STIX matches. |
| `report.csv` | General observation rows. |
| `subdomains.csv` | Names, observed IPs, passive sources, current DNS status, A answers, aliases, wildcard flag. |
| `new-subdomains.csv` | Names absent from the previous saved browser snapshot of the same domain. |
| `observed-ports.csv` | One row per passive port lead. |
| `cve-leads.csv` | One row per unverified IP/CVE association. |
| `ip-exposure.csv` | Per-IP passive ports, software hints, CVEs, and hostnames. |
| `dns-posture.csv` | DNS record observations. |
| `web-posture.csv` | Authorized HTTPS header/control observations. |
| `locations.csv` | Per-provider IP location points and reported spread. |
| `ip-neighbors.csv` | Shared-IP hostnames, separated from subdomains. |
| `source-log.csv` | Source, status, time, and reference for reproducibility. |
| `report.stix.json` | STIX 2.1 observable bundle and note when present. |

Exports contain the **current enriched case**. To include passive port/CVE leads, DNS posture, deep discovery, or the authorized HTTPS result, run those buttons before exporting. No scanner can invent missing source data.

The **Local scanner** workspace has a separate ZIP export because it describes devices on the user's connected private network, not the public-IP investigation. Its `report.html` is a formatted, printable table; `scan.json` contains the scan plan, per-device state counts, and findings; and `ports.csv` contains the responsive or uncertain rows. Closed ports are counted in JSON rather than emitted as thousands of table rows. A banner or HTTP `Server` header is self-reported evidence, not a verified software inventory.

## Recommended finding workflow

1. Verify that the domain and IP are within written program scope.
2. Separate current DNS from historical names and shared-IP neighbors.
3. For a port lead, confirm the live service and version through an authorized method.
4. For a CVE lead, verify product/version match, affected configuration, reachable attack surface, and impact. A database association alone is **not** a vulnerability report.
5. For a missing header or DNS policy, check application context and whether it creates a meaningful security issue. Absence alone is not necessarily reportable.
6. Record evidence, uncertainty, reproduction steps, and remediation in analyst notes before submission.

The map's provider spread circle is the geographic distance between the source-reported points. It is not a statistical confidence radius and does not identify an individual or server location.
