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
| Desktop UI | Browser/API exposure and untrusted asset markup | Native Qt Widgets calls the controller directly; normal startup has no listener or webview. Asset values are plain text. The obsolete website was removed. |
| Optional local API | Unauthorised scans, inventory reads/writes, CSRF and DNS rebinding | Explicit enable from Tools; loopback binding only, random per-enable token in `X-Discovr-Token`, exact Host validation, no CORS, JSON-only mutations, 32 connection limit and bounded request bodies. Closing Discovr stops the listener. |
| Untrusted reports | Script in HTML, formula injection in CSV, malformed imported identities | HTML values and inert JSON conversion data are escaped; HTML imports parse data without rendering scripts. CSV cells and headers neutralise formulas, and imported booleans/counts retain their types. CSV/JSON/Discovr HTML imports are bounded to 32 MB / 65,536 assets and validated before mutation. |
| Active Directory | Password captured by sniffing or by an attacker in the middle; account lockout | A simple bind (which carries the password) only happens inside a TLS channel whose certificate and hostname **verified** (system trust store, or `--ca-file` with the domain CA); otherwise NTLM challenge-response, which never sends the password; one bind attempt per mechanism; password prompted (or `DISCOVR_AD_PASSWORD`), never logged, stored or echoed |
| Cloud APIs | Long-lived or over-privileged credentials | Credentials supplied at runtime through native form fields or provider chains; read-only list calls; Azure pagination restricted to its HTTPS API origin; minimum permissions documented in the README |
| Target networks | Disruption of fragile devices | Bounded TCP connects and timeouts (`--intensity gentle`); Standard mode also reads SSH banners, bounded HTTP responses and targeted unicast UPnP descriptions. No authentication, redirects, multicast searches or UPnP control requests. Passive mode sends nothing. |
| Local machine | Privilege abuse | No elevation or separately installed executable needed; OS ARP/route readers use fixed paths and argument lists without a shell. Local OS/interface/listener facts are read when permitted; no packet-capture driver is loaded. |
| Supply chain | Vulnerable dependencies | Small dependency set, `pip-audit` in CI, UPX disabled, SHA-256 checksums published with releases |

## Data handling and privacy

- Discovr sends nothing anywhere except to the systems you ask it to query. It has no
  telemetry, update checks or third-party web requests; the desktop loads no remote UI content.
- Inventory lives in memory while the desktop runs; files are written only when you save or
  export through a native file dialog (the optional CLI uses `Documents/discovr_reports`, or `--out`). Reports contain IPs, hostnames, MAC
  addresses and cloud metadata - treat them as confidential.
- Data minimisation: AD `description` fields are not collected (admins sometimes store
  passwords there).
- The API token grants access to the current inventory and scan controls. Copy it only to
  trusted local integrations; it is never embedded in URLs or reports. Disabling the API
  stops new connections; already accepted work may complete. Disabling does not cancel
  desktop jobs. Use Stop all to cancel scans. Closing the integration dialog alone keeps
  the API enabled until explicitly disabled or the app exits.
- Demo inventory uses reserved addresses and fake provider IDs in a separate session.
  Live scans and report import are disabled there; every sample row carries `Demo: true`.

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
- **Remote OS/device descriptions are hints.** A device can withhold or falsify its advertised
  identity. Anonymous HTTPS discovery accepts self-signed certificates and does not verify
  the device's TLS identity; it sends no credentials and reads at most 32 KiB per response.
- **Binaries are not code-signed yet**; verify downloads with `SHA256SUMS.txt`.

- **Runtime credentials** entered in the desktop remain in process memory during a scan.
  Password fields clear after successful submission, and completed jobs retain no credential objects.
  Existing provider SDK login caches are controlled by those providers. Python cannot
  guarantee that freed secret memory has been physically zeroed.
- **Inventory identity** isolates cloud resources by provider identity. LAN correlation is
  heuristic; do not combine unrelated networks with reused IPs in one session.
- **Driver-free passive observation** reads cached neighbours. It sends nothing, but cannot
  establish current liveness or discover devices absent from the operating system's cache.
