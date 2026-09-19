# Changelog

## 2.1.0-rc.1 (2026-09-19)

- Identify this computer from OS facts and local listeners; read bounded HTTP/SSH/UPnP hints
  from remote devices and recognise default gateways without external tools.
- Add Identify selected and explain unchecked, filtered, incomplete and closed-port results.
- Separate Reset filters from Clear results; cancelling and clearing rejects late scan callbacks.
- Add visible CSV/HTML/JSON buttons and offline report conversion, including safe HTML data round trips.

- Stream responding network hosts before the sweep finishes; add Quick/Standard discovery.
- Move scan preparation and file import off the GUI thread; cache filtering and IP sort keys.
- Preserve table selection while streaming, clear the saved indicator correctly, and show progress/warnings inline.
- Add environment labels, CIDR filters and a separate guided offline demo with marked exports.
- Remove the obsolete website; add an explicitly enabled local REST API for inventory integrations.
- Build optional Windows/Linux single files alongside the faster USB folders; test both after relocation.
- Publish a requirements matrix, illustrated guide, reproducible demo and performance measurements.

- Replace browser startup with a native Qt Widgets desktop on Windows, Linux and macOS.
- Preserve all six discovery sources, live inventory, filtering, scan warnings and cancellation.
- Add native import/export dialogs, atomic report writes and unsaved-inventory protection on close.
- Ship self-contained USB folders and macOS app bundles without a webview or default HTTP listener.
- Remove nmap integration, raw capture and Scapy; no optional install requirements remain.
- Load the runtime in place on every OS, with a native macOS launcher; gate startup time in CI.

- Add driver-free passive neighbour-cache observation and native AWS/Azure credential fields.
- Keep overlapping cloud private addresses separate using provider resource identities.
- Preserve full DNS names and avoid ambiguous hostname merges.
- Correct cloud VM classification and refresh changing inventory fields on repeat scans.
- Add cooperative cancellation, partial results and visible coverage warnings to cloud/AD scans.
- Bound DNS, SSH fingerprinting and local HTTP work.
- Validate malformed API/import payloads and conflicting command-line modes.
- Protect Azure bearer tokens against unexpected pagination origins and redirects.
- Include IPv6 public-address evidence and GCP's default ingress source in exposure hints.
- Lock and audit runtime dependencies; build and smoke-test Windows, Linux and both macOS architectures.
- Add offline packaged-provider diagnostics and draft-only release publishing.
