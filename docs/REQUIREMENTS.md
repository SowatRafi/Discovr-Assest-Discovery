# Requirements and acceptance map

Source: **Asset Discovery – Discovr**, four-page project brief supplied by the owner.
This matrix covers every bullet in Functional Requirements, Constraints & Limitations,
Must Haves, Nice to Haves and Optional Outcomes. Implementation is distinct from validation
against a particular customer's infrastructure.

The owner's later choices govern three changes: native desktop instead of a website;
no nmap/capture-driver/provider-CLI installation; fast USB folders first, with optional
single-file Windows/Linux builds. macOS Intel and Apple silicon are additional targets.

## Functional requirements (brief page 2)

| Requirement | Implementation and evidence | Boundary |
| --- | --- | --- |
| Lightweight, portable, minimal setup | Bundled native Qt app, double-click launcher, folder and single-file packages; relocated empty-PATH acceptance | Requires a supported desktop OS and permission to execute. Package size/start time are measured, not assumed negligible. |
| Inventory agent-capable hosts | TCP, AD, AWS and Azure results merge into one inventory; OS/role/AgentCapable, cloud agent context | Capability is a heuristic. Discovr does not verify that EDR is installed or certify compatibility with a vendor's agent. |
| Identify non-agent devices | Printer, network, IoT, mobile and other role rules; classification tests and demo | Best effort from available ports, names and metadata; not guaranteed device identification. |
| Active and passive discovery | Built-in TCP connections plus driver-free OS neighbour-cache observation; network/passive tests | Passive means cache observation, not packet sniffing. IPv4 network scope; cached entries may be stale. |
| Clear exportable IP/hostname/OS/role report | Native table/evidence details; visible CSV/HTML/JSON buttons, offline import/conversion and complete JSON save; packaged round-trip checks | Unidentified fields include reasons. HTML is an optional report file, not the app interface. |
| Open-source foundations | Python sockets/asyncio, ldap3, provider SDKs, Qt/PySide6; exact dependencies and licence notices | nmap was removed to satisfy the owner's no-extra-software instruction. |
| Simple GUI or CLI | Native source form, subnet detection, progressive options, stop/progress, filters, help/demo; desktop-only launch | The CLI was removed at the user’s request; all discovery runs through the native desktop. |
| AWS/Azure VM discovery | Regional/subscription inventory, runtime authentication, VM/agent/firewall context; provider fixtures | Real tenant access and permissions must be validated with owner credentials. |

## Constraints and limitations (brief page 3)

| Constraint | Implementation and evidence | Boundary |
| --- | --- | --- |
| No lengthy install/persistent environment changes; portable single binary | Fast folder launches in place; optional Windows/Linux single files; no installer, PATH changes, services or registry configuration | Single-file builds extract temporary libraries on launch and remove them on clean exit. OS caches/security checks and user-saved reports are outside a “no traces whatsoever” guarantee. |
| Minimal topology knowledge, preferably unprivileged | Use local subnet, editable scope, ordinary TCP sockets/cache reads | Auto-detection covers the default-route interface, not every routed VLAN/VPN. Missing documentation cannot reveal inaccessible networks. |
| Runtime cloud credentials, no assumed long-term access | AWS key/secret/session token, Azure tenant/client secret, GCP key file; existing SDK credentials remain optional | Cloud API connectivity and authorised credentials are inherently required; provider CLI is not. |
| Configurable scope/intensity | IP/CIDR/list, custom ports, Quick/Standard, Gentle/Normal/Aggressive, cancellation | Even gentle TCP traffic can affect fragile devices. Cancel cannot revoke a request already in flight. |
| Open source, no commercial library dependency | MIT project; pinned open-source dependencies; bundled third-party notices and Qt replacement/source instructions | Publisher signing identities are separate from application dependencies. |
| Windows/Linux execution | Windows x64 and Linux x64 native builds plus both macOS architectures | Linux baseline is a glibc desktop such as Ubuntu 22.04+, not Alpine/musl or a headless machine. macOS baseline: 14 ARM / 15 Intel. |

## Must haves (brief page 3)

| Must have | Delivery / verification |
| --- | --- |
| Single binary Windows/Linux | Optional `discovr-single-windows-x64.exe` and `discovr-single-linux-x64`; copied alone to a path with spaces and tested with empty PATH. Fast folder remains recommended. |
| On-premises and AWS/Azure agent-capable assets | Network/AD/AWS/Azure inventory and classification; merge and provider tests. |
| Runtime cloud authentication | Native credential forms and SDK credential support; secrets excluded from inventory/jobs/reports. |
| Configurable active/passive modes | Scope, ports, intensity, detail, passive duration and Stop controls. Passive coverage is limited as described above. |
| Results and export | Native sortable/filterable inventory, details, CSV/JSON/HTML, complete save and re-import. |
| Open-source tools/libraries | Runtime lock, licence notices, dependency audit. |
| Minimalistic GUI or CLI | Native widgets, first-use demo, local subnet button, inline errors; no webview. |
| Active Directory querying | LDAP paging, OS/OU/logon/enabled/stale/DC context, DNS resolution; internal CA support and offline directory tests. Real-domain acceptance remains environment dependent. |

## Nice to haves (brief page 4)

| Nice to have | Delivery / verification |
| --- | --- |
| Non-agent asset identification | Route-table gateway recognition, bounded SSH/HTTP/UPnP product evidence and role heuristics, with clearly labelled remote OS guesses and Identify selected. |
| Role/IP-range/environment grouping | Device-type filter; CIDR search (including imported IPv6 records); operator Environment label/filter and ScanScope metadata. Labels do not establish identity across unrelated overlapping LANs. |
| Parallel scanning | Bounded asynchronous TCP workers, up to four independent discovery jobs, concurrent provider operations, bounded DNS/SSH workers. |
| Well-designed web UI with filtering/export | **Replaced by the owner's native-desktop requirement.** Equivalent inventory, filtering, export and detail workflows are native; obsolete website assets are deleted. |

## Optional outcomes (brief page 4)

| Optional outcome | Delivery / verification |
| --- | --- |
| Preliminary risk from OS version, ports or missing patches | Implemented using OS-name/support heuristics, ports and cloud allow rules. Missing patches and vulnerabilities are **not** verified; the brief's alternatives do not require pretending otherwise. |
| Additional cloud providers | GCP Compute Engine inventory with project/zone identity and firewall context; fixtures and packaged SDK diagnostics. |
| REST API or plugin integration | Explicitly enabled, token-authenticated loopback REST API sharing desktop inventory; [endpoints and example](API.md). API tests cover auth, host validation, import/export, scan/cancel and shutdown. No vendor-specific CMDB connector is claimed. |

## Acceptance and remaining external checks

Automated coverage includes real loopback discovery, provider/directory fixtures, cancellation,
partial results, malformed data, report injection protection, native widget interaction,
demo isolation and authenticated API integration. Packaged checks exercise all four target
platforms and both optional single files. See the linked PR/CI results for the exact revision.

Live AD/AWS/Azure/GCP tenant acceptance and publisher signing/notarisation remain external
release checks. The code cannot manufacture valid credentials, discover unreachable hosts,
guarantee instantaneous results, or bypass OS execution policy. These are visible limits,
not hidden download requirements.
