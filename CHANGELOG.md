# Changelog

## 2.1.0 (unreleased)

- Ship USB app folders with a Windows GUI launcher, a macOS app bundle, and a dashboard Quit button.
- Remove nmap integration, raw capture and Scapy; no optional install requirements remain.
- Load the bundled runtime in place instead of extracting it on every launch.

- Add driver-free passive neighbour-cache observation and dashboard AWS/Azure credentials.
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
