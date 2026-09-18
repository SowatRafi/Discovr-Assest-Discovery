# Discovr

**Portable asset discovery for security-tool rollouts.** Build an inventory of machines that may need to be
running your security agent - on the network, in Active Directory and in AWS, Azure and GCP -
from one small binary with a local web dashboard. No installer, no agents, no internet
connection needed for local discovery. Cloud discovery requires access to the provider's APIs.

[![build](https://github.com/SowatRafi/Discovr-Assest-Discovery/actions/workflows/build.yml/badge.svg?branch=Rejuvinate-Discovr)](https://github.com/SowatRafi/Discovr-Assest-Discovery/actions/workflows/build.yml)

![Discovr dashboard](docs/screenshot.png)

## Why Discovr

When an organisation deploys EDR or any other security agent, it rarely knows its whole
estate, so agents land on a subset of machines and the rest stay invisible. Discovr answers
one question quickly, in an unfamiliar environment, with minimal setup:
**which hosts exist, which of them can run an agent, and which need attention first?**

## Highlights

- **One file, three operating systems** - standalone binaries for Windows x64, macOS (Apple
  silicon and Intel), and Linux x64. Python is bundled; users do not install it.
- **Fast, unprivileged network sweep** - an asyncio TCP engine needs no nmap, admin rights or
  Npcap; an ARP-cache pass also finds firewalled hosts on the local segment. Gentle / normal /
  aggressive profiles protect sensitive networks.
- **Several sources, one inventory** - active network, passive observation, Active Directory, AWS,
  Azure and GCP. Cloud resources use provider identities so overlapping private addresses stay separate.
- **Answers the rollout question** - every asset gets a type (Workstation, Server, Printer,
  IoT, ...), an **Agent-capable** flag and a triage **risk** rating. Cloud VMs show whether the
  AWS SSM or Azure VM agent is reporting, i.e. whether an agent can be pushed remotely.
- **Local web dashboard** - filters, search, detail view, CSV / JSON / HTML export and JSON
  import. Works fully offline.
- **Secure by default** - the UI listens on 127.0.0.1 only, behind a per-launch token; AD
  passwords are only sent over verified TLS (else NTLM); cloud credentials are supplied at runtime
  and stay in memory; reports neutralise CSV and HTML injection. See [SECURITY.md](SECURITY.md).

## Quick start

### Portable binary

1. Download the file for your system from the
   [Releases](https://github.com/SowatRafi/Discovr-Assest-Discovery/releases) page
   (`discovr-windows-x64.exe`, `discovr-macos-arm64`, `discovr-macos-x64` or `discovr-linux-x64`), and check it
   against `SHA256SUMS.txt`.
2. Run it:
   - **Windows** - double-click the `.exe` (or run it from PowerShell).
   - **macOS / Linux** - `chmod +x discovr-*` then `./discovr-macos-arm64` (or `-linux-x64`).
3. Your browser opens the dashboard. Keep the terminal window open; press **Ctrl+C** or close
   it to stop Discovr.

The binaries are not code-signed yet: on Windows choose *More info → Run anyway* in
SmartScreen; on macOS right-click → *Open* once, or run
`xattr -d com.apple.quarantine ./discovr-macos-arm64`.

The default network scan and passive neighbour-cache observation require no installer,
Python, nmap, packet-capture driver or administrator rights. AD needs directory credentials;
cloud needs authorised runtime credentials. Full packet capture and nmap OS detection are
optional advanced modes with additional system requirements.

Builds run on Windows, Ubuntu 22.04, macOS 14 (Apple silicon), and macOS 15 (Intel).
Use the matching architecture. Binaries unpack their bundled runtime into a temporary
directory while running; that directory must be writable and allow execution.

### From source (Python 3.13)

```bash
git clone https://github.com/SowatRafi/Discovr-Assest-Discovery.git
cd Discovr-Assest-Discovery
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install --require-hashes -r requirements.lock
python -m discovr                    # web dashboard
python -m discovr --help             # command line
```

## Web dashboard

Running Discovr without options starts the dashboard and opens it in your default browser.
The terminal shows the address, e.g. `http://127.0.0.1:53817/#token=...` - the token part is a
private per-launch key, so share neither the link nor screenshots of it.

- **New scan** (left) - pick a source, fill in the few fields it needs and start. Several scans
  can run at once; each shows live progress, the number of assets found and a *Stop* button.
- **Incomplete** means that a region, subscription or optional metadata could not be read.
  Review the warnings on that scan card. Missing firewall data is labelled **Unknown**.
  Stop preserves discovered assets; a cloud/directory request already in flight finishes
  before cancellation takes effect. Authentication may also take time to return.
- **Filters** (top) - search any field (`/` jumps to the search box), filter by risk, device
  type, source or agent capability. Tiles, breakdowns and the table always agree with the filters.
- **Risk breakdown / Device types** - click a row to filter by it.
- **Assets** - sortable table; select a hostname for every field Discovr knows about it.
- **Export** - CSV, JSON (re-importable) or a self-contained HTML report of the *filtered* view.
  **Import JSON** merges reports from other runs, e.g. a headless scan from a jump box.

`--port 8080` fixes the port and `--no-browser` skips opening a browser.

## Command line

Every scan is also available headless - handy for servers, SSH sessions and scripts.

```bash
discovr --autoipaddr                                   # sweep the local subnet
discovr --scan-network 10.10.0.0/22 --intensity gentle # sensitive network
discovr --scan-network 10.0.0.5,10.0.1.0/24 --ports 22,3389,5985-5986
discovr --scan-network 192.168.1.0/24 --os-detect      # + nmap -O (needs nmap and admin/root)
discovr --ad --domain corp.local --username auditor@corp.local        # password is prompted
discovr --cloud aws                                    # every enabled region
discovr --cloud azure --subscription <id>              # omit --subscription to scan all
discovr --cloud gcp --project my-project --gcp-credentials key.json
discovr --passive --timeout 300                       # observe OS cache, no driver
discovr --passive --packet-capture --iface eth0 --timeout 300  # full capture, optional
discovr --scan-network 10.0.0.0/24 --save yes --format all --out ./reports
```

(From source, replace `discovr` with `python -m discovr`.)

| Option | Purpose |
|---|---|
| *(none)*, `--ui`, `--port`, `--no-browser` | Web dashboard |
| `--scan-network RANGE`, `--autoipaddr` | Active network sweep of a CIDR / IP / list (up to a /16), or of the local subnet |
| `--ports`, `--intensity`, `--parallel`, `--os-detect` | Port list, load profile, probes in flight, nmap OS fingerprinting |
| `--ad --domain --username [--dc] [--ldaps] [--ca-file]` | Active Directory computers (password: prompt, or `DISCOVR_AD_PASSWORD`) |
| `--cloud aws [--profile] [--region all]` | EC2 instances |
| `--cloud azure [--subscription]` | Azure virtual machines |
| `--cloud gcp [--project] [--zone] [--gcp-credentials]` | Compute Engine instances |
| `--passive [--timeout]` | Observe the OS neighbour cache without sending packets |
| `--passive --packet-capture [--iface] [--timeout]` | Capture ARP/DHCP/mDNS traffic; needs capture support |
| `--diagnostics` | Offline validation of bundled providers and UI files; prints JSON |
| `--save yes/no`, `--format csv/json/html/both/all`, `--out DIR` | Reports (default: CSV + JSON in `Documents/discovr_reports`) |

Without `--save`, Windows asks whether to save (auto-saving after 15 seconds) and macOS/Linux
save automatically. CLI exit codes: `0` success, `1` failure, `2` invalid arguments or
incomplete cloud/directory coverage (partial reports are still saved), `130` interrupted.

## Discovery sources

### Network (active)

1. **Sweep** every address on 10 discovery ports. Any answer - an open port *or* an immediate
   refusal - proves the host is up. Plain TCP connects need no raw sockets, so no admin rights.
2. **ARP cache** - the sweep made the OS resolve every local address, so hosts whose firewall
   drops all TCP still appear, with their MAC address.
3. **Fingerprint** live hosts on 44 common service ports while reverse DNS runs in parallel; SSH
   banners and exposed services give an OS guess (Windows, domain controller, Ubuntu, iOS, ...).
4. **Optional `--os-detect`** hands the live hosts to a single batched `nmap -O` run.

| Intensity | Probes in flight | Timeout | Use for |
|---|---|---|---|
| gentle | 64 | 2 s | Fragile or monitored networks (OT, clinical, legacy) |
| normal | 512 | 1 s | Default |
| aggressive | 2,048 | 0.5 s | Large ranges when speed matters more than noise |

Worst-case sweep time is roughly *addresses × 10 ÷ probes in flight × timeout*: a silent /24
takes about 5 s at *normal*. Silent addresses dominate, and live hosts answer in milliseconds.

### Passive

The default observes the operating system's neighbour cache across local interfaces.
It sends nothing and needs no additional software or elevated rights. Records are explicitly
marked as cached evidence: entries may be stale, and this mode cannot see silent devices
that the operating system has not learned about. It observes IPv4 neighbours.

Enable **Use packet capture** or `--packet-capture` to listen for ARP, DHCP (hostname + vendor-class OS fingerprint), mDNS, NetBIOS,
LLMNR and SSDP, which is how devices announce themselves. It needs packet-capture rights:
Administrator plus [Npcap](https://npcap.com) on Windows, root on macOS/Linux.

### Active Directory

Lists every computer account with OS, OU, last logon, enabled/stale state and domain-controller
role, then resolves IPs. The password is only sent inside a TLS channel whose certificate
verified (add `--ca-file corp-ca.pem` if your domain CA is not in the system trust store);
otherwise Discovr authenticates with NTLM. It is never stored. A normal domain user account is
enough.

### Cloud (credentials resolved at runtime, read-only)

| Provider | Uses | Minimum permissions |
|---|---|---|
| AWS | Dashboard access key + secret + optional session token; existing profiles, environment variables or instance role | `ec2:DescribeRegions`, `ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`, `ssm:DescribeInstanceInformation` |
| Azure | Dashboard tenant/client ID + client secret; existing `az login`, AZURE_* environment variables or managed identity | built-in **Reader** role on the subscription(s) |
| GCP | `gcloud auth application-default login`, `GOOGLE_APPLICATION_CREDENTIALS`, `--gcp-credentials key.json` | **Compute Viewer** (`roles/compute.viewer`) |

Discovr lists virtual machines across all regions / subscriptions / zones and joins their
security groups, NSGs or firewall rules. **Ports** shows what the firewall allows,
**ExposedPorts** what the inspected allow rules permit from all internet addresses.
These are potential exposures, not connectivity tests: routing, NAT, load balancers,
deny rules, priorities and higher-level policies are not fully evaluated. Inspect
**ExposureAssessment** alongside the result. An empty finding does not prove isolation.

The dashboard credential fields avoid installing AWS/Azure command-line tools. Leave them
blank to use an existing provider login. Prefer temporary AWS credentials and an Azure
application granted Reader access. Credential fields are cleared after starting a scan;
credentials are not written to reports. Azure currently targets the public Azure cloud.

## How assets are classified

- **Type** (`[Workstation]`, `[Server]`, `[Printer]`, `[IoT]`, `[Network]`, `[Mobile]`,
  `[Tablet]`, `[WebHost]`, `[Unknown]`) comes from the OS name, hostname, open ports and cloud
  metadata.
- **Agent-capable** is set for workstations and servers: the hosts a security agent can run on.
- **Risk** is a triage heuristic, not a vulnerability scan:

| Risk | When |
|---|---|
| Critical | Unsupported OS (XP-8.1, Server 2003-2012, CentOS 7/8), or an admin / database / file-share port open to the internet |
| High | Other internet exposure, Windows 10 (end of support Oct 2025), Telnet/FTP, IoT and printers, RDP/VNC on endpoints |
| Medium | Servers, network gear, unidentified devices |
| Low | Current, supported desktops (Windows 11, macOS) |

Local records merge by IP/MAC or an unambiguous full hostname when one record lacks an IP.
DNS suffixes are preserved. Cloud records merge by provider, account/subscription/project,
region/zone and instance ID. They are kept separate from LAN records because a private IP
alone cannot establish that they are the same machine. A precise OS name beats a port-based
guess. Repeat scans update state and exposure; they do not delete assets absent from a scan.
Keep inventories from unrelated on-premises networks separate when their addresses overlap.

## Reports

`CSV`, `JSON` and `HTML` land in `Documents/discovr_reports/{csv,json,html}` (or `--out DIR`);
every run also writes a log to `.../logs`. Each field any source reported becomes a column.
JSON reports can be re-imported into the dashboard.

## Building and development

```bash
pip install --require-hashes -r requirements.lock
pip install -r requirements-dev.txt
python -m pytest -q                          # unit + integration tests (no network needed)
python scripts/rebuild_macos_crypto.py       # Intel macOS: static OpenSSL; no-op elsewhere
pyinstaller --noconfirm discovr.spec         # -> dist/discovr(.exe)
python scripts/smoke_binary.py dist/discovr.exe  # use dist/discovr on macOS/Linux
docker build -t discovr .                    # CLI in a container
```

GitHub Actions (`.github/workflows/build.yml`) tests on Windows, macOS and Linux, audits
the locked dependencies with `pip-audit`, and builds four binaries. Each executable is
copied outside the repository and tested with an empty PATH: provider diagnostics, dashboard,
loopback scan, export/import and shutdown. A `v*` tag prepares a **draft** release with SHA-256
checksums for maintainer review. No public release is published automatically.

See [upgrade notes](docs/UPGRADE.md) for design decisions, validation and remaining release gates.

```
discovr/
  cli.py        command line (and UI launcher)      server.py  local web server + REST API
  network.py    async TCP sweep engine              passive.py listen-only discovery
  active_directory.py  LDAP                         aws.py / azure.py / gcp.py  cloud providers
  core.py       merge, export, reporting            tagger.py / risk.py  classification
  ui/           dashboard (HTML/CSS/JS, no build step)
```

## Responsible use

Only scan networks, directories and cloud accounts you own or are explicitly authorised to
assess. Active scanning can trip intrusion-detection systems; agree the scope and timing with
the network owner first, and prefer `--intensity gentle` or passive mode on fragile networks.

## License

[MIT](LICENSE). The portable binaries also bundle third-party open-source libraries (including
Scapy, GPL-2.0, and ldap3, LGPL-3.0) under their own licences. Run `discovr --licenses`
to read bundled notices and the upstream release/source links for the exact package versions.
