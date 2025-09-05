# Discovr - Asset Discovery Tool

Discovr is a cross-platform asset discovery tool for **network, cloud, Active Directory, and passive sniffing environments**.  
It actively scans networks, queries cloud APIs, enumerates Active Directory computers, and passively sniffs traffic.  
Every discovered asset is enriched with **Tags** (Workstation, Server, IoT, Mobile, etc.) and a **Risk rating** (Critical, High, Medium, Low).  
Results can be exported to CSV/JSON, with feature-specific logs saved per run.  

---

## 🔹 Arguments and Combinations

| Feature | Argument(s) | Description | Example |
|---------|-------------|-------------|---------|
| **Network** | `--scan-network <CIDR>` | Scan a network range. | `--scan-network 192.168.1.0/24` |
| | `--ports <list>` | Limit scan to specific ports. | `--scan-network 192.168.1.0/24 --ports 22,80,443` |
| | `--parallel <N>` | Use parallel workers (default=1). | `--scan-network 192.168.1.0/24 --parallel 10` |
| | `--autoipaddr` | Auto-detect local IP/subnet. | `--autoipaddr` |
| | Combo | Can combine with `--ports` + `--parallel`. | `--autoipaddr --ports 22,80 --parallel 5` |
| **Cloud** | `--cloud aws --profile <p> --region <r>` | Discover AWS assets. | `--cloud aws --profile default --region us-east-1` |
| | `--cloud azure --subscription <id>` | Discover Azure assets. | `--cloud azure --subscription 1234-5678` |
| **AD** | `--ad --domain <d> --username <u> --password <p>` | Discover Active Directory assets. | `--ad --domain my.local --username user@my.local --password pass` |
| **Passive** | `--passive --iface <iface>` | Run passive sniffing. | `--passive --iface "Wi-Fi"` |
| | `--timeout <s>` | Timeout in seconds (default=180). | `--passive --iface "Wi-Fi" --timeout 60` |
| | Interactive | Run without `--iface`, choose interactively. | `--passive` |

---

## 🔹 Example Runs and Outputs

### 🌐 Network Discovery

#### 1. Auto-detect subnet + parallel workers
```bash
python -m discovr.cli --autoipaddr --parallel 10
```
Output:
```text
[+] Logs saved at logs\discovr_network_log_20250905_233903.log
[+] Auto-detected local subnet: 172.20.10.0/28
[+] Scanning network: 172.20.10.0/28 with 10 parallel workers
[+] Running OS detection scan (requires admin privileges)
    [+] Found: 172.20.10.8 (Unknown) | OS: Apple macOS 11 or iOS 16 | Ports: 22,88,445,5000,7000
    [+] Found: 172.20.10.2 (Unknown) | OS: Unknown | Ports: None
    [+] Found: 172.20.10.1 (Unknown) | OS: Apple iOS 15.0 - 16.1 | Ports: 21,53,49152,62078
    [+] Found: 172.20.10.3 (Unknown) | OS: Microsoft Windows 10 - 11 | Ports: 135,139,445,3389

Discovered Assets (final report):
+-------------+------------+---------------------+---------------------+---------------+--------+
| IP          | Hostname   | OS                  | Ports               | Tag           | Risk   |
+-------------+------------+---------------------+---------------------+---------------+--------+
| 172.20.10.8 | Unknown    | Apple macOS 11 or iOS 16 | 22,88,445,5000,7000 | [Workstation] | High   |
| 172.20.10.2 | Unknown    | Unknown             | None                | [Unknown]     | Medium |
| 172.20.10.1 | Unknown    | Apple iOS 15.0-16.1 | 21,53,49152,62078   | [Mobile]      | High   |
| 172.20.10.3 | Unknown    | Windows 10 - 11     | 135,139,445,3389    | [Workstation] | Medium |
+-------------+------------+---------------------+---------------------+---------------+--------+

[+] 4 active assets discovered out of 16 scanned hosts.
```

#### 2. Manual subnet + ports
```bash
python -m discovr.cli --scan-network 192.168.1.0/24 --ports 22,80,443 --parallel 5
```
Output (example):
```text
[+] Logs saved at logs\discovr_network_log_20250905_233950.log
[+] Scanning network: 192.168.1.0/24 with 5 parallel workers
[+] Running OS detection scan (requires admin privileges)
    [+] Found: 192.168.1.1 (router) | OS: Linux/Unix | Ports: 80,443
    [+] Found: 192.168.1.10 (laptop01) | OS: Windows 10 Pro | Ports: 22

Discovered Assets (final report):
+-------------+-----------+---------------+-------+--------------+--------+
| IP          | Hostname  | OS            | Ports | Tag          | Risk   |
+-------------+-----------+---------------+-------+--------------+--------+
| 192.168.1.1 | router    | Linux/Unix    | 80,443| [Network]    | Medium |
| 192.168.1.10| laptop01  | Windows 10 Pro| 22    | [Workstation]| Medium |
+-------------+-----------+---------------+-------+--------------+--------+

[+] 2 active assets discovered out of 256 scanned hosts.
```

#### Test Run
```bash
python -m tests.test_network
```
Output:
```text
[+] Running Network Discovery Test (Simulated)
    [+] Found: 192.168.1.1 (router) | OS: Linux/Unix | Ports: 80,443
    [+] Found: 192.168.1.10 (laptop01) | OS: Windows 10 Pro | Ports: 135,445
    [+] Found: 192.168.1.20 (server01) | OS: Linux 5.x kernel | Ports: 22,80,443

Discovered Assets (final report):
+---------------+-----------+-------------------+-----------+--------------+----------+
| IP            | Hostname  | OS                | Ports     | Tag          | Risk     |
+---------------+-----------+-------------------+-----------+--------------+----------+
| 192.168.1.1   | router    | Linux/Unix        | 80,443    | [Network]    | Medium   |
| 192.168.1.10  | laptop01  | Windows 10 Pro    | 135,445   | [Workstation]| Medium   |
| 192.168.1.20  | server01  | Linux 5.x kernel  | 22,80,443 | [Server]     | Medium   |
+---------------+-----------+-------------------+-----------+--------------+----------+

[+] 3 active assets discovered out of 256 scanned hosts.
```

---

### ☁️ Cloud Discovery

#### AWS Run
```bash
python -m discovr.cli --cloud aws --profile default --region us-east-1
```
Output:
```text
[+] Logs saved at logs\discovr_cloud_log_20250905_234000.log
[+] Discovering AWS assets...
    [+] AWS Instance: 54.12.34.56 (webserver01) | OS: Amazon Linux
    [+] AWS Instance: 10.0.0.12 (dbserver01) | OS: Windows Server 2019

Discovered Assets (final report):
+-------------+-------------+--------------+-------+---------+--------+
| IP          | Hostname    | OS           | Ports | Tag     | Risk   |
+-------------+-------------+--------------+-------+---------+--------+
| 54.12.34.56 | webserver01 | Amazon Linux | N/A   | [Server]| Low    |
| 10.0.0.12   | dbserver01  | Windows 2019 | N/A   | [Server]| Medium |
+-------------+-------------+--------------+-------+---------+--------+

[+] 2 cloud assets discovered.
```

#### Azure Run
```bash
python -m discovr.cli --cloud azure --subscription 12345678-abcd-1234-efgh-9876543210ab
```
Output:
```text
[+] Logs saved at logs\discovr_cloud_log_20250905_234100.log
[+] Discovering AZURE assets...
    [+] Azure VM: 20.50.30.10 (azureweb01) | OS: Ubuntu 20.04
    [+] Azure VM: 10.0.0.5 (azuresql01) | OS: Windows Server 2022

Discovered Assets (final report):
+-------------+--------------+---------------------+-------+---------+--------+
| IP          | Hostname     | OS                  | Ports | Tag     | Risk   |
+-------------+--------------+---------------------+-------+---------+--------+
| 20.50.30.10 | azureweb01   | Ubuntu 20.04        | N/A   | [Server]| Low    |
| 10.0.0.5    | azuresql01   | Windows Server 2022 | N/A   | [Server]| Low    |
+-------------+--------------+---------------------+-------+---------+--------+

[+] 2 cloud assets discovered.
```

#### Test Run
```bash
python -m tests.test_cloud
```
Output:
```text
[+] Running Cloud Discovery Test (Simulated)
    [+] Simulated AWS VM: 54.12.34.56 (aws-web01) | OS: Amazon Linux
    [+] Simulated AWS VM: 10.0.0.12 (aws-db01) | OS: Windows Server 2019
    [+] Simulated Azure VM: 20.50.30.10 (azure-app01) | OS: Ubuntu 20.04
    [+] Simulated Azure VM: 10.0.0.5 (azure-sql01) | OS: Windows Server 2022

Discovered Assets (final report):
+-------------+--------------+---------------------+-------+---------+--------+
| IP          | Hostname     | OS                  | Ports | Tag     | Risk   |
+-------------+--------------+---------------------+-------+---------+--------+
| 54.12.34.56 | aws-web01    | Amazon Linux        | N/A   | [Server]| Low    |
| 10.0.0.12   | aws-db01     | Windows Server 2019 | N/A   | [Server]| Medium |
| 20.50.30.10 | azure-app01  | Ubuntu 20.04        | N/A   | [Server]| Low    |
| 10.0.0.5    | azure-sql01  | Windows Server 2022 | N/A   | [Server]| Low    |
+-------------+--------------+---------------------+-------+---------+--------+

[+] 4 cloud assets discovered (simulated).
```

---

### 🏢 Active Directory Discovery

#### Real Run
```bash
python -m discovr.cli --ad --domain mydomain.local --username admin@mydomain.local --password "Secret123"
```
Output:
```text
[+] Logs saved at logs\discovr_ad_log_20250905_234200.log
[+] Discovering Active Directory assets in mydomain.local
    [+] AD Computer: 192.168.1.25 (HR-PC01.mydomain.local) | OS: Windows 10 Pro
    [+] AD Computer: 192.168.1.30 (DB-SERVER01.mydomain.local) | OS: Windows Server 2019

Discovered Assets (final report):
+--------------+-----------------------------+--------------------+-------+--------------+----------+
| IP           | Hostname                    | OS                 | Ports | Tag          | Risk     |
+--------------+-----------------------------+--------------------+-------+--------------+----------+
| 192.168.1.25 | HR-PC01.mydomain.local      | Windows 10 Pro     | N/A   | [Workstation]| Medium   |
| 192.168.1.30 | DB-SERVER01.mydomain.local  | Windows Server 2019| N/A   | [Server]     | Medium   |
+--------------+-----------------------------+--------------------+-------+--------------+----------+

[+] 2 Active Directory assets discovered.
```

#### Test Run
```bash
python -m tests.test_active_directory
```
Output:
```text
[+] Running Active Directory Discovery Test (Simulated)
    [+] Simulated AD Computer: 192.168.1.25 (HR-PC01.mydomain.local) | OS: Windows 10 Pro
    [+] Simulated AD Computer: 192.168.1.30 (DB-SERVER01.mydomain.local) | OS: Windows Server 2019
    [+] Simulated AD Computer: 192.168.1.40 (DEV-LAPTOP.mydomain.local) | OS: Windows 11 Pro

Discovered Assets (final report):
+--------------+-----------------------------+--------------------+-------+--------------+----------+
| IP           | Hostname                    | OS                 | Ports | Tag          | Risk     |
+--------------+-----------------------------+--------------------+-------+--------------+----------+
| 192.168.1.25 | HR-PC01.mydomain.local      | Windows 10 Pro     | N/A   | [Workstation]| Medium   |
| 192.168.1.30 | DB-SERVER01.mydomain.local  | Windows Server 2019| N/A   | [Server]     | Medium   |
| 192.168.1.40 | DEV-LAPTOP.mydomain.local   | Windows 11 Pro     | N/A   | [Workstation]| Low      |
+--------------+-----------------------------+--------------------+-------+--------------+----------+

[+] 3 Active Directory assets discovered (simulated).
```

---

### 📡 Passive Discovery

#### Real Run
```bash
python -m discovr.cli --passive --iface "Wi-Fi" --timeout 60
```
Output:
```text
[+] Logs saved at logs\discovr_passive_log_20250905_234400.log
[+] Running passive discovery
    [+] Passive Discovery Found: 192.168.1.50 (printer.local) | OS: Unknown
    [+] Passive Discovery Found: 192.168.1.60 (iot-camera.local) | OS: Unknown
    [+] Passive Discovery Found: 192.168.1.70 (Johns-iPhone) | OS: iOS 16

Discovered Assets (final report):
+-------------+-------------------+----------+-------+---------+--------+
| IP          | Hostname          | OS       | Ports | Tag     | Risk   |
+-------------+-------------------+----------+-------+---------+--------+
| 192.168.1.50| printer.local     | Unknown  | N/A   | [Printer]| High   |
| 192.168.1.60| iot-camera.local  | Unknown  | N/A   | [IoT]    | High   |
| 192.168.1.70| Johns-iPhone      | iOS 16   | N/A   | [Mobile] | Medium |
+-------------+-------------------+----------+-------+---------+--------+

[+] 3 assets discovered during passive monitoring.
```

#### Test Run
```bash
python -m tests.test_passive
```
Output:
```text
[+] Running Passive Discovery Test (Simulated)
    [+] Simulated Passive Asset: 192.168.1.50 (printer.local)
    [+] Simulated Passive Asset: 192.168.1.60 (iot-camera.local)

Discovered Assets (final report):
+-------------+-------------------+----------+-------+---------+--------+
| IP          | Hostname          | OS       | Ports | Tag     | Risk   |
+-------------+-------------------+----------+-------+---------+--------+
| 192.168.1.50| printer.local     | Unknown  | N/A   | [Printer]| High   |
| 192.168.1.60| iot-camera.local  | Unknown  | N/A   | [IoT]    | High   |
+-------------+-------------------+----------+-------+---------+--------+

[+] 2 assets discovered during passive monitoring (simulated).
```

---

## 🔹 Platform Notes

- **Windows:** Run PowerShell as **Administrator**. Use interface names like `"Wi-Fi"`, `"Ethernet"`.  
- **Linux/Mac:** Run with `sudo`. Interfaces are `eth0`, `en0`, `wlan0`.  
- **Timeout:** Passive default = 180s. Override with `--timeout <seconds>`.  
- **Parallel:** Default 1. Recommended 5–20.  
- **AutoIPAddr:** Automatically finds your local subnet.  

---
