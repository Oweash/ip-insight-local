# Data sources and evidence limits

| Source | Data used | Key limitation |
|---|---|---|
| [Google Public DNS](https://developers.google.com/speed/public-dns/docs/doh/json) | Current resolver answers, DNS posture, selected subdomain A checks | Answers vary by resolver, place, and time. |
| [crt.sh](https://crt.sh/) and [Cert Spotter](https://sslmate.com/certspotter/) | Certificate transparency names | Certificates can contain historical names and wildcards. |
| [HackerTarget](https://hackertarget.com/) | Host search and reverse IP hostnames | Shared hosts can be unrelated to the target organization. |
| [AlienVault OTX](https://otx.alienvault.com/api) | Passive DNS observations | An observation may be stale or unavailable without an account. |
| [urlscan.io](https://urlscan.io/docs/api/) | Public scan domain observations | Search results are public, incomplete, historical, and quota limited. |
| [Shodan InternetDB](https://book.shodan.io/developer-apis/internetdb/) | Passive ports, software hints, hostnames, CVE associations | Not a live port scan; CVEs can be unverified associations. |
| Connected device scan (localhost only) | Live ping, TCP connection, UDP response, local neighbor-table MAC, limited banner/HTTP/TLS clues | Requires authorization; silent UDP is ambiguous and self-reported versions need validation. |
| Public IP geolocation providers | Provider coordinates and names | Network geolocation is approximate, and providers may disagree. |
| [ipify](https://www.ipify.org/) | Visitor's public IP in the connection strip | Reports the internet-facing address seen by its service, which may be a VPN or shared gateway. |
| [IPWhois](https://ipwhois.io/documentation), [GeoJS](https://www.geojs.io/), [ipapi.is](https://ipapi.is/), [FreeIPAPI](https://freeipapi.com/) | First available approximate visitor area in the connection strip | City and region can be inaccurate; browser requests send the visitor's public IP to the selected service. |
| RDAP / public WHOIS / routing services | Registration and routing context | Records identify network operators or allocations, not individual users. |
| [OpenFreeMap / MapLibre](https://openfreemap.org/) | Interactive base map | Map tiles require internet access. |

Each provider lookup is recorded in the source log with its time and status. A failed provider is not silently treated as a negative finding. Deep discovery merges up to 1,000 passive names and checks A records for up to 32 prioritized names. The app limits the number of IP addresses enriched in one investigation, and shows when results are truncated. No passive source can enumerate **every** subdomain or location for a website.

The authorized HTTPS check is distinct from passive sources: it sends one `HEAD /` request and one `GET /.well-known/security.txt` request to the exact entered hostname. It does not follow redirects. A missing security header, absent `security.txt`, or observed certificate field is context for review, not proof of exploitability. The `security.txt` path and format follow [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html); the header review is informed by [MDN HTTP Observatory](https://developer.mozilla.org/en-US/observatory).
