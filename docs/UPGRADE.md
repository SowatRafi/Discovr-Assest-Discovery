# Portable reliability upgrade (2.1)

The original Discovr brief prioritises lightweight Windows/Linux execution, discovery of
agent-capable hosts, network/AD/AWS/Azure sources and exportable reports. This upgrade also
targets macOS on Intel and Apple silicon.

## Keep Python for this release

The USB package bundles Python and its dependencies in a ready-to-run folder (a `.app`
bundle on macOS). Double-click the launcher; no separately installed runtime is used.
PyInstaller's [one-folder model](https://pyinstaller.org/en/stable/operating-mode.html)
loads libraries directly from the drive on Windows/Linux, avoiding per-launch extraction.
The macOS app uses a single bundled executable: it extracts to the Mac's own temporary
storage so its USB copy does not depend on filesystem support for framework symbolic links.
A Go rewrite is not needed to meet the no-install requirement. Reconsider it only if
measurements on target hardware justify replacing the working LDAP and cloud integrations.

USB startup cannot be literally instantaneous: device speed and operating-system scanning
still matter. First-run security approval and Linux USB execution permissions are controlled
by the host. The application cannot bypass them. See [USB instructions](USB-START.txt).

## Behaviour changes

- Cloud identities are scoped by provider and resource identity, avoiding collisions on
  reused private IPs. Full DNS names preserve domain boundaries. Ambiguous names stay separate.
- Cloud VMs are classified before interpreting firewall port ranges as device evidence.
- Repeated scans refresh power state, addresses and firewall exposure.
- AD and cloud scans accept Stop, stream results, and expose incomplete coverage. Cancellation
  occurs between requests; in-flight requests and authentication can delay completion.
- DNS lookups have caller deadlines and a bounded daemon worker pool. Stalled system DNS
  cannot hold the application open. SSH banner concurrency is bounded too.
- nmap, raw packet capture and Scapy are removed. Every exposed mode works without installing tools.
- Passive discovery watches the OS neighbour cache. Windows uses its built-in ARP reader without flashing a console.
- The dashboard Quit button stops the process before the USB drive is ejected.
- AWS/Azure credentials can be supplied through the dashboard without installing provider CLIs.
- Invalid API payloads fail before modifying inventory. API connections and scan history are bounded.
- Runtime dependencies are pinned with hashes and audited. Platform builds exercise the packaged
  application after relocation and with an empty PATH.

## Validation boundaries

Automated tests use loopback listeners, provider API fixtures and an offline LDAP directory.
They cover application logic, not access to a specific customer's network or tenancy.
Packaged diagnostics check that provider libraries and required AWS service models are packaged;
they make no authenticated API calls and are not a credential test.

Before declaring a signed general-availability release, perform these environment checks:

1. Verify AD paging, internal CA trust and user permissions on a real test domain.
2. Compare AWS/Azure/GCP VM counts with provider consoles, including denied regions or
   subscriptions, stopped VMs, multiple NICs and overlapping private addresses.
3. Verify double-click launch on the intended USB drives and OS security policies. Compare
   cache observation with its explicitly narrower coverage; verify Quit releases the drive.
4. Review release checksums, dependency notices and platform binaries; code-sign Windows and
   sign/notarise macOS builds using the owner's signing identities.

The application does not infer installed EDR coverage or patch levels. AgentCapable is a
role/OS heuristic, not confirmation that a particular agent supports the device. Risk is
triage, not a vulnerability result. Cloud allow rules suggest potential exposure; they do
not model every firewall/routing layer or prove external reachability.

## Maintenance

Use a feature branch and a pull request. Keep fixes accompanied by tests for actual failure
modes. Commit with the maintainer's Git identity; do not add automated co-author trailers.
Do not store credentials, customer inventories or local tooling state in Git.

Update the runtime lock with Python 3.13 and pip-tools, review the dependency diff, then run
the test suite, dependency audit and all platform build checks. Release tags create drafts.

```sh
pip-compile --generate-hashes --no-emit-index-url --no-emit-trusted-host --strip-extras \
  --output-file requirements.lock requirements.txt
python -m pytest -q
pip-audit -r requirements.lock --disable-pip --no-deps
```

Runner architectures are selected explicitly using GitHub's
[hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

Intel macOS builds must run `python scripts/rebuild_macos_crypto.py` before PyInstaller.
It rebuilds the hash-locked cryptography source with `OPENSSL_STATIC=1`, bypasses cached
dynamic wheels and verifies the result with `otool`. This avoids a collision between
Homebrew and Python's different `libssl.3.dylib` versions. Homebrew OpenSSL and Rust are
build-time requirements on that platform; users still receive a self-contained app bundle.
See cryptography's [static-build instructions](https://cryptography.io/en/latest/installation/).
