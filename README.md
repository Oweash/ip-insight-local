# IP Insight Local

![IP Insight logo](dist/logo.png)

IP Insight Local is a browser-based investigation workbench for **public IP addresses and domains**. It runs on your own computer at `http://127.0.0.1:4173`. It joins passive network and hostname observations, compares source-reported IP locations, stores recent investigations in your browser, and exports evidence-rich case bundles.

The app is for asset triage and authorized research. It does not reveal a person's private IP or precise physical location, prove domain ownership from a shared IP, or confirm an exploitable vulnerability from a CVE association.

## Start

1. Install [Node.js 22 or newer](https://nodejs.org/en/download).
2. Open a terminal in this folder.
3. Run `npm ci` and then `npm start`.
4. Open [http://127.0.0.1:4173](http://127.0.0.1:4173).

On Windows, you can also double-click `START-WINDOWS.cmd` after Node.js is installed. The server binds to `127.0.0.1` only. Internet access is required for public lookup services and map tiles. Set `IP_INSIGHT_PORT` to another port if 4173 is occupied. `.env.example` lists optional settings; set them as environment variables in your terminal before starting the server. Do not commit secrets.

## What it does

- Investigates a domain, a public IP, or both; compares current DNS answers and source-reported IP locations without treating map points as exact locations.
- Finds passive subdomain names from certificate transparency, host search, passive DNS, and public web scan records. Deep discovery checks current A records for up to 32 prioritized names and flags wildcard DNS matches.
- Shows shared-IP neighbors separately from subdomains, with explicit ownership uncertainty.
- Retrieves passive port, software hint, hostname, and CVE leads from Shodan InternetDB. CVEs remain **unverified associations**.
- Reviews NS, MX, SPF, DMARC, and CAA records.
- On an authorized domain, makes two read-only HTTPS requests for headers, certificate metadata, and `/.well-known/security.txt`. Redirects are not followed; the connection is pinned to a validated public IPv4 DNS answer.
- Saves the latest 30 cases in browser storage, supports notes and snapshot comparison, and imports STIX 2.1 indicators for exact matching.
- Exports a single ZIP with a formatted HTML report, editable DOCX, JSON, CSV tables, STIX JSON, and source log. Open `report.html` and print it to PDF.

## Documentation

- [Product brief and proposed use](docs/PRODUCT_BRIEF.md)
- [Architecture and local data flow](docs/ARCHITECTURE.md)
- [Data sources and limits](docs/DATA_SOURCES.md)
- [Authorization, privacy, and security](docs/SECURITY_AND_SCOPE.md)
- [Report fields and interpretation](docs/REPORTING.md)
- [Readiness assessment and roadmap](docs/ROADMAP.md)
- [Vulnerability reporting for this project](SECURITY.md)

## Development

`npm test` runs unit and route tests. `npm run build` refreshes browser vendor assets and copies the browser history module into `dist`. The checked-in `dist` assets make the downloaded package immediately runnable. The app uses Node's standard HTTP server, a shared Web API investigation core, MapLibre GL JS, and JSZip. No paid API is required. An optional server-side `ABUSEIPDB_API_KEY` adds live reputation context; keep it in the environment, never in browser code or Git.

The current local edition uses browser-local history. Google sign-in and the previous hosted Site's cloud history are not part of this localhost package. The previous hosted URL is a separate deployment and is not required to run this project.

## License status

This repository is public for viewing and review. It has no project license yet, so public visibility alone does not grant redistribution or modification rights. Third-party library notices are in [dist/licenses.txt](dist/licenses.txt). The project owner can choose a license before accepting external contributions.
