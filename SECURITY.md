# Security model

Discovr is run by security teams inside environments they do not fully know, handles
directory and cloud credentials, and ingests data from the network that an attacker can
influence. This page states what it protects, how, and where the limits are.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (Security tab → *Report a
vulnerability*) instead of a public issue. Include steps to reproduce and the affected version.

## Trust boundaries and controls

| Boundary | Threat | Control |
|---|---|---|
| Browser ↔ local UI server | Other websites driving the API (CSRF), DNS rebinding, other local users | Listens on `127.0.0.1` only; per-launch random token required in an `X-Discovr-Token` header (a custom header cannot be sent cross-site without a CORS preflight, and no CORS headers are ever returned); `Host` must be `127.0.0.1`/`localhost`; JSON bodies only; token compared in constant time |
| Token handling | Leaking the session key | Token travels in the URL *fragment* (never sent to servers or in `Referer`), is stripped from the address bar on load, and lives only in that tab's `sessionStorage` |
| Untrusted asset data (hostnames, mDNS/DHCP names, AD attributes, cloud tags, imported JSON) | XSS in the dashboard, script in HTML reports, formula injection in CSV | Dashboard builds every node with `textContent` (no `innerHTML` with data) under a strict Content-Security-Policy (`script-src 'self'`); HTML reports escape every key and value; CSV cells *and column headers* starting with `= + - @` are prefixed with `'` |
| Active Directory | Password captured by sniffing or by an attacker in the middle; account lockout | A simple bind (which carries the password) only happens inside a TLS channel whose certificate and hostname **verified** (system trust store, or `--ca-file` with the domain CA); otherwise NTLM challenge-response, which never sends the password; one bind attempt per mechanism; password prompted (or `DISCOVR_AD_PASSWORD`), never logged, stored or echoed |
| Local API robustness | Memory or thread exhaustion by a local client or a hostile imported report | Request bodies are always consumed and capped at 32 MB (negative or non-numeric lengths and chunked uploads are refused); 30 s socket timeout against slow-drip clients; port ranges clamped to 1-65535 before expansion |
| Cloud APIs | Long-lived or over-privileged credentials | Credentials supplied at runtime through dashboard fields or provider chains; read-only list calls; Azure pagination restricted to its HTTPS API origin; minimum permissions documented in the README |
| Target networks | Disruption of fragile devices | Bounded concurrency and timeouts (`--intensity gentle`), TCP connects only (no malformed packets), passive mode sends nothing |
| Local machine | Privilege abuse | No elevation needed except for packet capture and `nmap -O`; subprocesses (`arp`, `nmap`) take argument lists (no shell) with validated IPs |
| Supply chain | Vulnerable dependencies | Small dependency set, `pip-audit` in CI, UPX disabled, SHA-256 checksums published with releases |

## Data handling and privacy

- Discovr sends nothing anywhere except to the systems you ask it to query. It has no
  telemetry, update checks or third-party web requests; the dashboard loads no CDN content.
- Inventory lives in memory while the dashboard runs; files are written only when you save or
  export (default `Documents/discovr_reports`, or `--out`). Reports contain IPs, hostnames, MAC
  addresses and cloud metadata - treat them as confidential.
- Data minimisation: AD `description` fields are not collected (admins sometimes store
  passwords there).

## Known limitations

- **Unverifiable domain controllers get NTLM.** When the DC certificate cannot be verified
  (no certificate, or an internal CA missing from the trust store), the password is still
  protected by NTLM challenge-response, but the directory listing travels unencrypted and an
  active attacker could relay the NTLM exchange. Pass `--ca-file` with the domain CA to get a
  verified TLS channel, and use a low-privilege account.
- **Cloud firewall analysis is partial**: the inspected allow rules suggest potential exposure.
  Deny rules, priorities, routing, NAT, load balancers and higher-level policies are not fully
  modelled. Results can over-report or miss exposure; an empty finding never proves isolation.
  Unavailable metadata is labelled Unknown and reported in scan warnings.
- **Risk ratings are heuristics** from OS names and open ports, not vulnerability findings.
- **Binaries are not code-signed yet**; verify downloads with `SHA256SUMS.txt`.

- **Runtime credentials** entered in the dashboard remain in process memory during a scan.
  The local API never returns them, and completed jobs retain no credential objects.
  Existing provider SDK login caches are controlled by those providers. Python cannot
  guarantee that freed secret memory has been physically zeroed.
- **Inventory identity** isolates cloud resources by provider identity. LAN correlation is
  heuristic; do not combine unrelated networks with reused IPs in one session.
- **Driver-free passive observation** reads cached neighbours. It sends nothing, but cannot
  establish current liveness or discover devices absent from the operating system's cache.
