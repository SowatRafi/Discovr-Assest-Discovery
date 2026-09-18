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
| Untrusted asset data (hostnames, mDNS/DHCP names, AD attributes, cloud tags, imported JSON) | XSS in the dashboard, script in HTML reports, formula injection in CSV | Dashboard builds every node with `textContent` (no `innerHTML` with data) under a strict Content-Security-Policy (`script-src 'self'`); HTML reports escape every value; CSV cells starting with `= + - @` are prefixed with `'` |
| Active Directory | Password sniffed on the LAN; account lockout | LDAPS, else StartTLS, else NTLM - never a cleartext simple bind; one bind attempt per mechanism; password prompted (or `DISCOVR_AD_PASSWORD`), never logged, stored or echoed |
| Cloud APIs | Long-lived or over-privileged credentials | Credentials only from each provider's runtime chain (`aws sso login`, `az login`, ADC); read-only list calls; minimum permissions documented in the README |
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

- **LDAP TLS certificates are not validated.** Most internal CAs are missing from the local
  trust store, so StartTLS/LDAPS encrypts but does not authenticate the domain controller. An
  attacker positioned on the LAN could intercept the bind. Use a trusted network or VPN, and a
  low-privilege account.
- **Cloud firewall analysis over-approximates**: deny rules and rule priorities are ignored, so
  exposure may be over-reported (never under-reported by a missing allow rule).
- **Risk ratings are heuristics** from OS names and open ports, not vulnerability findings.
- **Binaries are not code-signed yet**; verify downloads with `SHA256SUMS.txt`.
