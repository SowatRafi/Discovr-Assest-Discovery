# Discovr - Asset Discovery Tool

Discovr is a cross-platform asset discovery tool for **network, cloud, Active Directory, and passive sniffing environments**.  
It actively scans networks, queries cloud APIs, enumerates Active Directory computers, and passively sniffs traffic.  
Every discovered asset is enriched with **Tags** (Workstation, Server, IoT, Mobile, etc.) and a **Risk rating** (Critical, High, Medium, Low).  
Results can be exported to CSV/JSON, with feature-specific logs saved per run.  

---

## 🔹 Arguments and Combinations

| **Feature**                       | **Argument(s)**         | **Description**                                                                                                         | **Example**                                                                         |
| --------------------------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| 🌐 **Network Discovery**          | `--scan-network <CIDR>` | Scan a specific network range.                                                                                          | `--scan-network 192.168.1.0/24`                                                     |
|                                   | `--ports <list>`        | Limit scan to specific ports (comma-separated).                                                                         | `--scan-network 192.168.1.0/24 --ports 22,80,443`                                   |
|                                   | `--parallel <N>`        | Use parallel workers for faster scanning (default=1).                                                                   | `--scan-network 192.168.1.0/24 --parallel 10`                                       |
|                                   | `--autoipaddr`          | Auto-detect local IP + subnet and scan it. Can combine with `--ports` or `--parallel`.                                  | `--autoipaddr --parallel 5`                                                         |
| ☁️ **Cloud Discovery (AWS)**      | `--cloud aws`           | Select AWS as provider.                                                                                                 | `--cloud aws --profile default --region us-east-1`                                  |
|                                   | `--profile <p>`         | AWS profile name (default=`default`).                                                                                   | `--cloud aws --profile myprofile --region us-west-2`                                |
|                                   | `--region <r>`          | AWS region to scan (default=`us-east-1`).                                                                               | `--cloud aws --profile default --region eu-west-1`                                  |
| ☁️ **Cloud Discovery (Azure)**    | `--cloud azure`         | Select Azure as provider.                                                                                               | `--cloud azure --subscription 12345678-abcd-1234-efgh-9876543210ab`                 |
|                                   | `--subscription <id>`   | Azure subscription ID.                                                                                                  | `--cloud azure --subscription 12345678-abcd-1234`                                   |
| ☁️ **Cloud Discovery (GCP)**      | `--cloud gcp`           | Select GCP as provider.                                                                                                 | `--cloud gcp --project my-gcp-project --zone us-central1-a`                         |
|                                   | `--project <id>`        | GCP project ID.                                                                                                         | `--cloud gcp --project my-gcp-project --zone us-central1-a`                         |
|                                   | `--zone <zone>`         | GCP zone in the project.                                                                                                | `--cloud gcp --project my-gcp-project --zone europe-west1-b`                        |
| 🏢 **Active Directory Discovery** | `--ad`                  | Run AD discovery.                                                                                                       | `--ad --domain mydomain.local --username admin@mydomain.local --password Secret123` |
|                                   | `--domain <d>`          | AD domain name.                                                                                                         | `--domain mydomain.local`                                                           |
|                                   | `--username <u>`        | AD username.                                                                                                            | `--username admin@mydomain.local`                                                   |
|                                   | `--password <p>`        | AD password.                                                                                                            | `--password Secret123`                                                              |
| 📡 **Passive Discovery**          | `--passive`             | Run passive discovery (sniff ARP, DNS, DHCP, mDNS).                                                                     | `--passive`                                                                         |
|                                   | `--iface <iface>`       | Specify network interface (interactive if not provided).                                                                | `--passive --iface "Wi-Fi"`                                                         |
|                                   | `--timeout <s>`         | Passive discovery timeout in seconds (default=180).                                                                     | `--passive --iface "Wi-Fi" --timeout 60`                                            |
| 📊 **Export System**              | *(Prompt after run)*    | Save results to CSV, JSON, or both. Filenames include feature + timestamp.                                              | `Choose format (csv/json/both): both`                                               |
| 🏷️ **Tagger**                    | *(Automatic)*           | Classifies assets: `[Workstation]`, `[Server]`, `[Mobile]`, `[Tablet]`, `[IoT]`, `[Printer]`, `[Network]`, `[WebHost]`. | Auto-tag applied after scan.                                                        |
| 🔐 **RiskAssessor**               | *(Automatic)*           | Assigns risk level (`Critical`, `High`, `Medium`, `Low`) based on OS, ports, and tags.                                  | Win7 + RDP → Critical; IoT + HTTP → High.                                           |


---

## 🔹 Example Runs and Outputs

🌐 Network Discovery — Example Runs and Outputs

This section documents **all possible argument combinations** for Network Discovery, with **real run simulated outputs** and **test run outputs**.  

---

### 1. Basic Run (`--scan-network`)
```bash
python -m discovr.cli --scan-network 192.168.1.0/24
```
Output:
```text
[+] Logs saved at logs\discovr_network_log_20250906_130000.log
[+] Scanning network: 192.168.1.0/24 with 1 parallel workers
[+] Running OS detection scan (requires admin privileges)
    [+] Found: 192.168.1.1 (router) | OS: Linux/Unix | Ports: 80,443
    [+] Found: 192.168.1.10 (laptop01) | OS: Windows 10 Pro | Ports: 135,445
    [+] Found: 192.168.1.20 (server01) | OS: Linux 5.x kernel | Ports: 22,80,443
    [+] Found: 192.168.1.30 (printer01) | OS: Unknown | Ports: 9100

Discovered Assets (final report):
+---------------+-----------+-------------------+-----------+--------------+--------+
| IP            | Hostname  | OS                | Ports     | Tag          | Risk   |
+---------------+-----------+-------------------+-----------+--------------+--------+
| 192.168.1.1   | router    | Linux/Unix        | 80,443    | [Network]    | Medium |
| 192.168.1.10  | laptop01  | Windows 10 Pro    | 135,445   | [Workstation]| Medium |
| 192.168.1.20  | server01  | Linux 5.x kernel  | 22,80,443 | [Server]     | Medium |
| 192.168.1.30  | printer01 | Unknown           | 9100      | [Printer]    | High   |
+---------------+-----------+-------------------+-----------+--------------+--------+

[+] 4 active assets discovered out of 256 scanned hosts.
[+] Total execution time: 23.12 seconds
[+] Logs saved at logs/discovr_network_log_20250906_130000.log

Do you want to save results? (yes/no): yes
Choose format (csv/json/both): both
[+] CSV saved: csv_report\discovr_network_20250906_130000.csv
[+] JSON saved: json_report\discovr_network_20250906_130000.json
```

---

### 2. Run with Ports (`--scan-network + --ports`)
```bash
python -m discovr.cli --scan-network 192.168.1.0/24 --ports 22,80,443
```
Output:
```text
[+] Logs saved at logs\discovr_network_log_20250906_130030.log
[+] Scanning network: 192.168.1.0/24 with 1 parallel workers
[+] Running port-specific scan (ports: 22,80,443)
    [+] Found: 192.168.1.1 (router) | OS: Linux/Unix | Ports: 80,443
    [+] Found: 192.168.1.20 (server01) | OS: Linux 5.x kernel | Ports: 22,80
    [+] Found: 192.168.1.50 (iot-device) | OS: Unknown | Ports: 443

Discovered Assets (final report):
+---------------+-----------+-------------------+-----------+--------------+--------+
| IP            | Hostname  | OS                | Ports     | Tag          | Risk   |
+---------------+-----------+-------------------+-----------+--------------+--------+
| 192.168.1.1   | router    | Linux/Unix        | 80,443    | [Network]    | Medium |
| 192.168.1.20  | server01  | Linux 5.x kernel  | 22,80     | [Server]     | Medium |
| 192.168.1.50  | iot-device| Unknown           | 443       | [IoT]        | High   |
+---------------+-----------+-------------------+-----------+--------------+--------+

[+] 3 active assets discovered out of 256 scanned hosts.
[+] Total execution time: 18.54 seconds
```

---

### 3. Run with Parallel (`--scan-network + --parallel`)
```bash
python -m discovr.cli --scan-network 192.168.1.0/24 --parallel 10
```
Output:
```text
[+] Logs saved at logs\discovr_network_log_20250906_130100.log
[+] Scanning network: 192.168.1.0/24 with 10 parallel workers
[+] Running OS detection scan (requires admin privileges)
    [+] Found: 192.168.1.1 (router) | OS: Linux/Unix | Ports: 80,443
    [+] Found: 192.168.1.10 (laptop01) | OS: Windows 11 Pro | Ports: 135,445
    [+] Found: 192.168.1.20 (server01) | OS: Linux 5.x kernel | Ports: 22,443
    [+] Found: 192.168.1.30 (macbook) | OS: macOS Ventura | Ports: 22,80

Discovered Assets (final report):
+---------------+-----------+-------------------+-----------+--------------+--------+
| IP            | Hostname  | OS                | Ports     | Tag          | Risk   |
+---------------+-----------+-------------------+-----------+--------------+--------+
| 192.168.1.1   | router    | Linux/Unix        | 80,443    | [Network]    | Medium |
| 192.168.1.10  | laptop01  | Windows 11 Pro    | 135,445   | [Workstation]| Low    |
| 192.168.1.20  | server01  | Linux 5.x kernel  | 22,443    | [Server]     | Medium |
| 192.168.1.30  | macbook   | macOS Ventura     | 22,80     | [Workstation]| Low    |
+---------------+-----------+-------------------+-----------+--------------+--------+

[+] 4 active assets discovered out of 256 scanned hosts.
[+] Total execution time: 7.89 seconds
```

---

### 4. Auto-detect Subnet (`--autoipaddr`)
```bash
python -m discovr.cli --autoipaddr
```
Output:
```text
[+] Logs saved at logs\discovr_network_log_20250906_130130.log
[+] Auto-detected local subnet: 172.20.10.0/28
[+] Scanning network: 172.20.10.0/28 with 1 parallel workers
[+] Running OS detection scan (requires admin privileges)
    [+] Found: 172.20.10.8 (Unknown) | OS: Apple macOS 12 or iOS 16 | Ports: 22,445,5000
    [+] Found: 172.20.10.3 (Unknown) | OS: Windows 10/11 | Ports: 135,139,445,3389
    [+] Found: 172.20.10.1 (Unknown) | OS: iOS 15 | Ports: 21,53,49152,62078

Discovered Assets (final report):
+-------------+------------+-----------------------------+---------------------+---------------+--------+
| IP          | Hostname   | OS                          | Ports               | Tag           | Risk   |
+-------------+------------+-----------------------------+---------------------+---------------+--------+
| 172.20.10.8 | Unknown    | Apple macOS 12 or iOS 16    | 22,445,5000         | [Workstation] | High   |
| 172.20.10.3 | Unknown    | Windows 10/11               | 135,139,445,3389    | [Workstation] | High   |
| 172.20.10.1 | Unknown    | iOS 15                      | 21,53,49152,62078   | [Mobile]      | High   |
+-------------+------------+-----------------------------+---------------------+---------------+--------+

[+] 3 active assets discovered out of 16 scanned hosts.
[+] Total execution time: 15.67 seconds
```

---

### 5. Auto-detect Subnet with Parallel (`--autoipaddr + --parallel`)
```bash
python -m discovr.cli --autoipaddr --parallel 10
```
Output:
```text
[+] Logs saved at logs\discovr_network_log_20250906_130200.log
[+] Auto-detected local subnet: 172.20.10.0/28
[+] Scanning network: 172.20.10.0/28 with 10 parallel workers
[+] Running OS detection scan (requires admin privileges)
    [+] Found: 172.20.10.8 (Unknown) | OS: Apple macOS 12 or iOS 16 | Ports: 22,445,5000
    [+] Found: 172.20.10.3 (Unknown) | OS: Windows 10/11 | Ports: 135,139,445,3389
    [+] Found: 172.20.10.1 (Unknown) | OS: iOS 15 | Ports: 21,53,49152,62078
    [+] Found: 172.20.10.2 (Unknown) | OS: Unknown | Ports: None

Discovered Assets (final report):
+-------------+------------+-----------------------------+---------------------+---------------+--------+
| IP          | Hostname   | OS                          | Ports               | Tag           | Risk   |
+-------------+------------+-----------------------------+---------------------+---------------+--------+
| 172.20.10.8 | Unknown    | Apple macOS 12 or iOS 16    | 22,445,5000         | [Workstation] | High   |
| 172.20.10.3 | Unknown    | Windows 10/11               | 135,139,445,3389    | [Workstation] | High   |
| 172.20.10.1 | Unknown    | iOS 15                      | 21,53,49152,62078   | [Mobile]      | High   |
| 172.20.10.2 | Unknown    | Unknown                     | None                | [Unknown]     | Medium |
+-------------+------------+-----------------------------+---------------------+---------------+--------+

[+] 4 active assets discovered out of 16 scanned hosts.
[+] Total execution time: 6.45 seconds
```

---

### Test Run (`tests/test_network`)
```bash
python -m tests.test_network
```
Output:
```text
[+] Running Network Discovery Test (Simulated)
    [+] Found: 192.168.1.1 (router) | OS: Linux/Unix | Ports: 80,443
    [+] Found: 192.168.1.10 (laptop01) | OS: Windows 10 Pro | Ports: 135,445
    [+] Found: 192.168.1.20 (server01) | OS: Linux 5.x kernel | Ports: 22,80,443
    [+] Found: 192.168.1.30 (printer01) | OS: Unknown | Ports: 9100

Discovered Assets (final report):
+---------------+-----------+-------------------+-----------+--------------+--------+
| IP            | Hostname  | OS                | Ports     | Tag          | Risk   |
+---------------+-----------+-------------------+-----------+--------------+--------+
| 192.168.1.1   | router    | Linux/Unix        | 80,443    | [Network]    | Medium |
| 192.168.1.10  | laptop01  | Windows 10 Pro    | 135,445   | [Workstation]| Medium |
| 192.168.1.20  | server01  | Linux 5.x kernel  | 22,80,443 | [Server]     | Medium |
| 192.168.1.30  | printer01 | Unknown           | 9100      | [Printer]    | High   |
+---------------+-----------+-------------------+-----------+--------------+--------+

[+] 4 active assets discovered out of 256 scanned hosts.
```

---


## ☁️ Cloud Discovery — Example Runs and Outputs

This section documents **all possible argument combinations** for Cloud Discovery (AWS, Azure, GCP), with **real run simulated outputs** and **test run outputs**.  

---

### 1. AWS Discovery (`--cloud aws --profile --region`)
```bash
python -m discovr.cli --cloud aws --profile default --region us-east-1
```
Output:
```text
[+] Logs saved at logs\discovr_cloud_log_20250906_140000.log
[+] Discovering AWS assets...
    [+] AWS Instance: 54.12.34.56 (aws-web01) | OS: Amazon Linux
    [+] AWS Instance: 10.0.0.12 (aws-db01) | OS: Windows Server 2019
    [+] AWS Instance: 10.0.0.20 (aws-dev01) | OS: Ubuntu 20.04

Discovered Assets (final report):
+-------------+-----------+---------------------+-------+---------+--------+
| IP          | Hostname  | OS                  | Ports | Tag     | Risk   |
+-------------+-----------+---------------------+-------+---------+--------+
| 54.12.34.56 | aws-web01 | Amazon Linux        | N/A   | [Server]| Low    |
| 10.0.0.12   | aws-db01  | Windows Server 2019 | N/A   | [Server]| Medium |
| 10.0.0.20   | aws-dev01 | Ubuntu 20.04        | N/A   | [Server]| Low    |
+-------------+-----------+---------------------+-------+---------+--------+

[+] 3 cloud assets discovered.
[+] Total execution time: 9.87 seconds
```

---

### 2. Azure Discovery (`--cloud azure --subscription`)
```bash
python -m discovr.cli --cloud azure --subscription 12345678-abcd-1234-efgh-9876543210ab
```
Output:
```text
[+] Logs saved at logs\discovr_cloud_log_20250906_140030.log
[+] Discovering AZURE assets...
    [+] Azure VM: 20.50.30.10 (azureweb01) | OS: Ubuntu 22.04
    [+] Azure VM: 10.0.0.5 (azuresql01) | OS: Windows Server 2022
    [+] Azure VM: 10.0.0.15 (azuredev01) | OS: Windows 11 Pro

Discovered Assets (final report):
+-------------+------------+---------------------+-------+--------------+--------+
| IP          | Hostname   | OS                  | Ports | Tag          | Risk   |
+-------------+------------+---------------------+-------+--------------+--------+
| 20.50.30.10 | azureweb01 | Ubuntu 22.04        | N/A   | [Server]     | Low    |
| 10.0.0.5    | azuresql01 | Windows Server 2022 | N/A   | [Server]     | Low    |
| 10.0.0.15   | azuredev01 | Windows 11 Pro      | N/A   | [Workstation]| Low    |
+-------------+------------+---------------------+-------+--------------+--------+

[+] 3 cloud assets discovered.
[+] Total execution time: 8.45 seconds
```

---

### 3. GCP Discovery (`--cloud gcp --project --zone`)
```bash
python -m discovr.cli --cloud gcp --project my-gcp-project --zone us-central1-a
```
Output:
```text
[+] Logs saved at logs\discovr_cloud_log_20250906_140100.log
[+] Discovering GCP assets in project: my-gcp-project (zone: us-central1-a)
    [+] GCP Instance: 34.122.12.34 (gcp-web01) | OS: Ubuntu 22.04
    [+] GCP Instance: 10.128.0.5 (gcp-db01) | OS: Windows Server 2019
    [+] GCP Instance: 10.128.0.10 (gcp-dev01) | OS: Debian 11

Discovered Assets (final report):
+-------------+-----------+-------------------+-------+---------+--------+
| IP          | Hostname  | OS                | Ports | Tag     | Risk   |
+-------------+-----------+-------------------+-------+---------+--------+
| 34.122.12.34| gcp-web01 | Ubuntu 22.04      | N/A   | [Server]| Low    |
| 10.128.0.5  | gcp-db01  | Windows Server 2019| N/A  | [Server]| Medium |
| 10.128.0.10 | gcp-dev01 | Debian 11         | N/A   | [Server]| Medium |
+-------------+-----------+-------------------+-------+---------+--------+

[+] 3 cloud assets discovered.
[+] Total execution time: 11.23 seconds
```

---

### 4. Test Runs

### Cloud Test (AWS + Azure)
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

### GCP Test
```bash
python -m tests.test_gcp
```
Output:
```text
[+] Running GCP Discovery Test (Simulated)
    [+] Simulated GCP Instance: 34.122.12.34 (gcp-web01) | OS: Ubuntu 22.04
    [+] Simulated GCP Instance: 10.128.0.5 (gcp-db01) | OS: Windows Server 2019

Discovered Assets (final report):
+-------------+-----------+-------------------+-------+---------+--------+
| IP          | Hostname  | OS                | Ports | Tag     | Risk   |
+-------------+-----------+-------------------+-------+---------+--------+
| 34.122.12.34| gcp-web01 | Ubuntu 22.04      | N/A   | [Server]| Low    |
| 10.128.0.5  | gcp-db01  | Windows Server 2019| N/A  | [Server]| Medium |
+-------------+-----------+-------------------+-------+---------+--------+

[+] 2 cloud assets discovered (simulated).
```

# 🏢 Active Directory Discovery — Example Runs and Outputs

This section documents **all possible argument combinations** for Active Directory Discovery, with **real run simulated outputs** and **test run outputs**.  

---

### 1. Real Run (`--ad --domain --username --password`)
```bash
python -m discovr.cli --ad --domain mydomain.local --username admin@mydomain.local --password "Secret123"
```
Output:
```text
[+] Logs saved at logs\discovr_ad_log_20250906_150000.log
[+] Discovering Active Directory assets in mydomain.local
    [+] AD Computer: 192.168.1.25 (HR-PC01.mydomain.local) | OS: Windows 10 Pro
    [+] AD Computer: 192.168.1.30 (DB-SERVER01.mydomain.local) | OS: Windows Server 2019
    [+] AD Computer: 192.168.1.40 (DEV-LAPTOP.mydomain.local) | OS: Windows 11 Pro

Discovered Assets (final report):
+--------------+-----------------------------+--------------------+-------+--------------+----------+
| IP           | Hostname                    | OS                 | Ports | Tag          | Risk     |
+--------------+-----------------------------+--------------------+-------+--------------+----------+
| 192.168.1.25 | HR-PC01.mydomain.local      | Windows 10 Pro     | N/A   | [Workstation]| Medium   |
| 192.168.1.30 | DB-SERVER01.mydomain.local  | Windows Server 2019| N/A   | [Server]     | Medium   |
| 192.168.1.40 | DEV-LAPTOP.mydomain.local   | Windows 11 Pro     | N/A   | [Workstation]| Low      |
+--------------+-----------------------------+--------------------+-------+--------------+----------+

[+] 3 Active Directory assets discovered.
[+] Total execution time: 6.34 seconds
[+] Logs saved at logs/discovr_ad_log_20250906_150000.log

Do you want to save results? (yes/no): yes
Choose format (csv/json/both): both
[+] CSV saved: csv_report\discovr_ad_20250906_150000.csv
[+] JSON saved: json_report\discovr_ad_20250906_150000.json
```

---

### 2. Missing Arguments Example (Error Handling)
```bash
python -m discovr.cli --ad --domain mydomain.local --username admin@mydomain.local
```
Output:
```text
[+] Logs saved at logs\discovr_ad_log_20250906_150030.log
[!] AD discovery requires --domain, --username, and --password
```

---

### 3. Test Run (`tests/test_active_directory`)
```bash
python -m tests.test_active_directory
```
Output:
```text
[+] Running Active Directory Discovery Test (Simulated)
    [+] Simulated AD Computer: 192.168.1.25 (HR-PC01.mydomain.local) | OS: Windows 10 Pro
    [+] Simulated AD Computer: 192.168.1.30 (DB-SERVER01.mydomain.local) | OS: Windows Server 2019
    [+] Simulated AD Computer: 192.168.1.40 (DEV-LAPTOP.mydomain.local) | OS: Windows 11 Pro
    [+] Simulated AD Computer: 192.168.1.50 (LAB-PC.mydomain.local) | OS: Windows 7 Pro

Discovered Assets (final report):
+--------------+-----------------------------+--------------------+-------+--------------+----------+
| IP           | Hostname                    | OS                 | Ports | Tag          | Risk     |
+--------------+-----------------------------+--------------------+-------+--------------+----------+
| 192.168.1.25 | HR-PC01.mydomain.local      | Windows 10 Pro     | N/A   | [Workstation]| Medium   |
| 192.168.1.30 | DB-SERVER01.mydomain.local  | Windows Server 2019| N/A   | [Server]     | Medium   |
| 192.168.1.40 | DEV-LAPTOP.mydomain.local   | Windows 11 Pro     | N/A   | [Workstation]| Low      |
| 192.168.1.50 | LAB-PC.mydomain.local       | Windows 7 Pro      | N/A   | [Workstation]| Critical |
+--------------+-----------------------------+--------------------+-------+--------------+----------+

[+] 4 Active Directory assets discovered (simulated).
```

---

# 📡 Passive Discovery — Example Runs and Outputs

This section documents **all possible argument combinations** for Passive Discovery, with **real run simulated outputs** and **test run outputs**.  

---

### 1. Interactive Mode (`--passive`)
```bash
python -m discovr.cli --passive
```
Output:
```text
[+] Logs saved at logs\discovr_passive_log_20250906_160000.log
[+] Running passive discovery
[+] Available interfaces:
    [1] Ethernet (Intel(R) Ethernet Controller)
    [2] Wi-Fi (Intel(R) Wi-Fi 6 AX200)
    [3] Loopback Pseudo-Interface 1

Select interface by number: 2
[+] Starting passive discovery on interface: Wi-Fi
[+] Listening for ARP, DNS, DHCP, and mDNS traffic (auto-stop after 180 seconds or Ctrl+C)...
    [+] Passive Discovery Found: 192.168.1.50 (printer.local)
    [+] Passive Discovery Found: 192.168.1.60 (iot-camera.local)
    [+] Passive Discovery Found: 192.168.1.70 (Johns-iPhone)
    [+] Passive Discovery Found: 192.168.1.80 (macbook.local)

Discovered Assets (final report):
+-------------+-------------------+----------+-------+--------------+--------+
| IP          | Hostname          | OS       | Ports | Tag          | Risk   |
+-------------+-------------------+----------+-------+--------------+--------+
| 192.168.1.50| printer.local     | Unknown  | N/A   | [Printer]    | High   |
| 192.168.1.60| iot-camera.local  | Unknown  | N/A   | [IoT]        | High   |
| 192.168.1.70| Johns-iPhone      | iOS 16   | N/A   | [Mobile]     | Medium |
| 192.168.1.80| macbook.local     | macOS 13 | N/A   | [Workstation]| Low    |
+-------------+-------------------+----------+-------+--------------+--------+

[+] 4 assets discovered during passive monitoring.
[+] Total execution time: 180.00 seconds
[+] Logs saved at logs/discovr_passive_log_20250906_160000.log

Do you want to save results? (yes/no): yes
Choose format (csv/json/both): both
[+] CSV saved: csv_report\discovr_passive_20250906_160000.csv
[+] JSON saved: json_report\discovr_passive_20250906_160000.json
```

---

### 2. Specific Interface with Timeout (`--passive --iface --timeout`)
```bash
python -m discovr.cli --passive --iface "Wi-Fi" --timeout 60
```
Output:
```text
[+] Logs saved at logs\discovr_passive_log_20250906_160030.log
[+] Running passive discovery
[+] Starting passive discovery on interface: Wi-Fi
[+] Listening for ARP, DNS, DHCP, and mDNS traffic (auto-stop after 60 seconds or Ctrl+C)...
    [+] Passive Discovery Found: 192.168.1.55 (printer.local)
    [+] Passive Discovery Found: 192.168.1.65 (iot-lightbulb.local)
    [+] Passive Discovery Found: 192.168.1.75 (samsung-galaxy)
    [+] Passive Discovery Found: 192.168.1.85 (macbook-air.local)

Discovered Assets (final report):
+-------------+-----------------------+----------+-------+--------------+--------+
| IP          | Hostname              | OS       | Ports | Tag          | Risk   |
+-------------+-----------------------+----------+-------+--------------+--------+
| 192.168.1.55| printer.local         | Unknown  | N/A   | [Printer]    | High   |
| 192.168.1.65| iot-lightbulb.local   | Unknown  | N/A   | [IoT]        | High   |
| 192.168.1.75| samsung-galaxy        | Android  | N/A   | [Mobile]     | Medium |
| 192.168.1.85| macbook-air.local     | macOS 12 | N/A   | [Workstation]| Low    |
+-------------+-----------------------+----------+-------+--------------+--------+

[+] 4 assets discovered during passive monitoring.
[+] Total execution time: 60.00 seconds
[+] Logs saved at logs/discovr_passive_log_20250906_160030.log
```

---

### 3. Test Run (`tests/test_passive`)
```bash
python -m tests.test_passive
```
Output:
```text
[+] Running Passive Discovery Test (Simulated)
    [+] Simulated Passive Asset: 192.168.1.50 (printer.local)
    [+] Simulated Passive Asset: 192.168.1.60 (iot-camera.local)
    [+] Simulated Passive Asset: 192.168.1.70 (iphone.local)

Discovered Assets (final report):
+-------------+-------------------+----------+-------+--------------+--------+
| IP          | Hostname          | OS       | Ports | Tag          | Risk   |
+-------------+-------------------+----------+-------+--------------+--------+
| 192.168.1.50| printer.local     | Unknown  | N/A   | [Printer]    | High   |
| 192.168.1.60| iot-camera.local  | Unknown  | N/A   | [IoT]        | High   |
| 192.168.1.70| iphone.local      | iOS 15   | N/A   | [Mobile]     | Medium |
+-------------+-------------------+----------+-------+--------------+--------+

[+] 3 assets discovered during passive monitoring (simulated).
```

## 🔹 Platform Notes

- **Windows:** Run PowerShell as **Administrator**. Use interface names like `"Wi-Fi"`, `"Ethernet"`.  
- **Linux/Mac:** Run with `sudo`. Interfaces are `eth0`, `en0`, `wlan0`.  
- **Timeout:** Passive default = 180s. Override with `--timeout <seconds>`.  
- **Parallel:** Default 1. Recommended 5–20.  
- **AutoIPAddr:** Automatically finds your local subnet.  

---

## 🔹 Build Executable
```bash
pyinstaller --onefile --name discovr discovr/cli.py
```

## 🔹 Dockerfile
```bash
docker build -t discovr .
```

## 🔹 requirements.txt
```bash
pip install -r requirements.txt
```

# Discovr - Non-Interactive Export Options (--save / --format)

This document demonstrates how to use the new `--save` and `--format` options with **Network Discovery**.

---

## 🔹 Arguments
- `--save yes` → Automatically save results without prompting.  
- `--save no` → Do not save results (skips prompts).  
- `--format csv` → Save only CSV file.  
- `--format json` → Save only JSON file.  
- `--format both` → Save both CSV and JSON.  

If no `--save` or `--format` is provided, Discovr remains **interactive** and will ask:  
```
Do you want to save results? (yes/no):
Choose format (csv/json/both):
```

---

## 🔹 Example Run (Network Discovery with --save and --format)

### Command
```bash
python -m discovr.cli --scan-network 192.168.1.0/24 --parallel 5 --save yes --format both
```

### Output
```text
[+] Logs saved at /Users/demo/Documents/discovr_reports/logs/discovr_network_log_20250906_230000.log
[+] Scanning network: 192.168.1.0/24 with 5 parallel workers
[+] Running OS detection scan (requires admin privileges)
    [+] Found: 192.168.1.1 (router) | OS: Linux/Unix | Ports: 80,443
    [+] Found: 192.168.1.10 (laptop01) | OS: Windows 10 Pro | Ports: 135,445
    [+] Found: 192.168.1.20 (server01) | OS: Linux 5.x kernel | Ports: 22,80,443

Discovered Assets (final report):
+---------------+-----------+-------------------+-----------+--------------+--------+
| IP            | Hostname  | OS                | Ports     | Tag          | Risk   |
+---------------+-----------+-------------------+-----------+--------------+--------+
| 192.168.1.1   | router    | Linux/Unix        | 80,443    | [Network]    | Medium |
| 192.168.1.10  | laptop01  | Windows 10 Pro    | 135,445   | [Workstation]| Medium |
| 192.168.1.20  | server01  | Linux 5.x kernel  | 22,80,443 | [Server]     | Medium |
+---------------+-----------+-------------------+-----------+--------------+--------+

[+] 3 active assets discovered out of 256 scanned hosts.
[+] Total execution time: 19.42 seconds
[+] Logs saved at /Users/demo/Documents/discovr_reports/logs/discovr_network_log_20250906_230000.log
[+] CSV saved: /Users/demo/Documents/discovr_reports/csv/discovr_network_20250906_230000.csv
[+] JSON saved: /Users/demo/Documents/discovr_reports/json/discovr_network_20250906_230000.json
```

---

## 🔹 Notes
- Works on all platforms (Windows, Linux, macOS).  
- Useful for **non-interactive runs** (e.g., cron jobs, macOS `sudo` execution, CI/CD).  
- Can be used with **any feature** (Network, Cloud, AD, Passive).  
