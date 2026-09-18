# Portable reliability upgrade (2.1)

The original Discovr brief prioritises lightweight Windows/Linux execution, discovery of
agent-capable hosts, network/AD/AWS/Azure sources and exportable reports. This upgrade also
targets macOS on Intel and Apple silicon.

## Keep Python for this release

The existing implementation already bundles Python and its libraries into a single file.
A Go rewrite would replace working LDAP and cloud integrations without eliminating the
operating-system privileges required by packet capture. Continue with the current codebase
and validate the executable itself. Reconsider Go only if measured startup, memory use or
deployment restrictions on temporary extraction justify the migration.

PyInstaller's [one-file model](https://pyinstaller.org/en/stable/operating-mode.html) extracts
the runtime to a temporary directory. It requires no separately installed Python, but is
not a static executable and cannot run where extraction/execution is prohibited.

## Behaviour changes

- Cloud identities are scoped by provider and resource identity, avoiding collisions on
  reused private IPs. Full DNS names preserve domain boundaries. Ambiguous names stay separate.
- Cloud VMs are classified before interpreting firewall port ranges as device evidence.
- Repeated scans refresh power state, addresses and firewall exposure.
- AD and cloud scans accept Stop, stream results, and expose incomplete coverage. Cancellation
  occurs between requests; in-flight requests and authentication can delay completion.
- DNS lookups have caller deadlines and a bounded daemon worker pool. Stalled system DNS
  cannot hold the application open. SSH banner concurrency is bounded too.
- nmap respects scan intensity and can be terminated by Stop.
- Passive discovery defaults to watching the OS neighbour cache. Packet capture is opt-in.
- AWS/Azure credentials can be supplied through the dashboard without installing provider CLIs.
- Invalid API payloads fail before modifying inventory. API connections and scan history are bounded.
- Runtime dependencies are pinned with hashes and audited. Platform builds exercise the packaged
  application after relocation and with an empty PATH.

## Validation boundaries

Automated tests use loopback listeners, provider API fixtures and an offline LDAP directory.
They cover application logic, not access to a specific customer's network or tenancy.
`--diagnostics` checks that provider libraries and required AWS service models are packaged;
it makes no authenticated API calls and is not a credential or capture-driver test.

Before declaring a signed general-availability release, perform these environment checks:

1. Verify AD paging, internal CA trust and user permissions on a real test domain.
2. Compare AWS/Azure/GCP VM counts with provider consoles, including denied regions or
   subscriptions, stopped VMs, multiple NICs and overlapping private addresses.
3. Verify packet capture on machines with supported capture facilities if that optional mode
   will be offered. Compare the driver-free cache mode with its explicitly narrower coverage.
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
