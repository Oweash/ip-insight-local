# Product brief

## Problem

Security researchers often have to switch among DNS tools, certificate logs, IP intelligence feeds, geolocation databases, and spreadsheets before they can decide which asset merits authorized follow-up. The data also has different freshness and ownership meaning. A shared IP can host unrelated organizations, and a historical subdomain record is not proof of a live asset.

## Proposed product

IP Insight Local brings those signals into one evidence-first investigation. The main workflow is: enter a public IP or domain, review current and historical relationships, compare provider-reported locations, optionally inspect passive exposure and DNS posture, run a bounded authorized HTTPS configuration check, record notes, and export a structured case bundle. A researcher can reopen recent cases from the same browser and compare discovered names across snapshots.

## Audience and use cases

- Bug bounty researchers triaging assets **within a program's written scope**.
- Defenders inventorying their own public DNS and IP exposure.
- Students demonstrating how to normalize, label, and report uncertain OSINT findings.

The app is not a penetration testing framework, exploit tool, source of exact physical locations, or proof that a hostname/IP belongs to a particular company.

## Value and differentiators

1. An evidence log records source, status, time, and reference for each lookup.
2. UI and reports separate current DNS answers, historical passive observations, shared-IP neighbors, and live authorized website checks.
3. Map points remain provider estimates; the displayed spread radius measures disagreement between provider coordinates, not a probability of the target being inside the circle.
4. Full case exports include human-readable reports plus machine-readable tables.
5. The entire app runs on localhost and its history stays in the browser profile.

## Acceptance criteria for this release

- Launches on Windows with Node.js and binds only to loopback.
- Rejects private target IPs in the main investigation and prevents the authorized website check from connecting to a domain with private IPv4 DNS answers.
- Labels CVEs, ports, missing headers, and historical names as leads.
- Exports subdomains, ports, CVEs, DNS, source log, notes, and a formatted report in one ZIP.
- Includes reproducible setup, architecture, security, data source, and reporting documentation.
