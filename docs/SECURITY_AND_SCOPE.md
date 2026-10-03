# Authorization, privacy, and security

## Intended scope

Use the app only for assets you own or are permitted to research. A discovered subdomain, IP neighbor, or historical certificate name does not automatically enter a bug bounty program's scope. Read the program rules before any active test. The optional HTTPS check requires an explicit authorization checkbox and makes two read-only requests to the entered domain.

## Local application protections

- The HTTP server listens on `127.0.0.1`, not a public interface. It checks the Host header and serves a fixed asset allowlist. The authorized HTTPS route requires a same-origin JSON POST, helping prevent other websites from triggering it.
- The main API validates domain syntax and rejects private input IPs.
- Before the authorized HTTPS check, the server resolves IPv4 addresses and refuses the check if **any** returned address is not public. Its HTTPS connection is pinned to one validated public address, reducing DNS rebinding and redirect risks. Redirects are not followed; TLS certificates are verified by Node.
- HTTPS check responses have timeouts, header limits, and bounded body capture. It does not crawl pages, enumerate paths, submit forms, authenticate to target sites, or exploit a service.
- Browser output uses text nodes for third-party values. The standalone report escapes source text before inserting it into HTML.
- `.env` files are ignored by Git. Optional AbuseIPDB credentials remain on the local server.

## Privacy and retention

Cases and notes are in this browser's localStorage, limited to 30 recent cases and subject to browser storage capacity. Anyone with access to the same browser profile may be able to view them. Clearing site data removes them. Exported ZIPs contain targets, source observations, analyst notes, and any imported indicator matches; handle those files according to the applicable program rules. The app does not send case history to the former hosted Site or Google account. It does send target queries to the public services listed in [DATA_SOURCES.md](DATA_SOURCES.md).

## Known gaps

- Browser localStorage is not encrypted or a substitute for a multi-user database.
- A local browser page can be reached by other software on the same PC. Avoid running untrusted local software while using sensitive case data.
- IP geolocation cannot identify an individual, private IP, physical device, or exact origin behind a CDN.
- Port and CVE data is passive and may be stale. No verification of service versions, CVSS, exploitability, or program scope is automated.
- The HTTPS check covers public IPv4 web endpoints only; it does not evaluate every header directive or TLS configuration.
- Automated third-party sources can impose quotas or change behavior. Failed lookups appear in the evidence log.

The [OWASP Web Security Testing Guide](https://wstg.owasp.org/) is a useful framework for an authorized human follow-up. IP Insight does not replace that methodology.

## Connected-network scan

The optional localhost scanner requires an explicit permission confirmation. The server accepts only a subnet calculated from one of the computer's currently connected private IPv4 interfaces. It will not accept a user-supplied target address, public subnet, or remote network. Scans are capped at 254 addresses, 20 TCP ports, and one active scan at a time. Discovery uses a single ping per address and bounded concurrent TCP connections. The server listens only on 127.0.0.1 and requires a same-origin request.

MAC addresses come from the operating system's local neighbor table or the computer's own network interface. Missing MAC addresses and devices that do not answer probes are expected. The scanner does not offer stealth, remote access, exploitation, or vulnerability confirmation.
