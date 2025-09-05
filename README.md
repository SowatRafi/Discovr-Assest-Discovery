# Discovr - Asset Discovery Tool

Discovr is a lightweight asset discovery tool for **network, cloud, Active Directory, and passive sniffing environments**.  
It can actively scan networks, detect hosts, guess operating systems, list open ports, discover assets in AWS and Azure, query Active Directory for computer objects, and passively sniff network traffic for devices.  
Results can be exported to CSV/JSON and logs are automatically created.  

---

## 🔹 Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--scan-network` | Network range in CIDR or single host | `--scan-network 192.168.1.0/24` |
| `--ports` | Comma-separated list of ports to scan | `--ports 22,80,443` |
| `--cloud` | Cloud provider (`aws` or `azure`) | `--cloud aws` |
| `--profile` | AWS profile name (default: `default`) | `--cloud aws --profile myprofile` |
| `--region` | AWS region (default: `us-east-1`) | `--cloud aws --region us-west-2` |
| `--subscription` | Azure subscription ID | `--cloud azure --subscription <sub-id>` |
| `--ad` | Run Active Directory discovery | `--ad --domain mydomain.local --username admin@mydomain.local --password "Secret123"` |
| `--domain` | AD domain name | `--domain mydomain.local` |
| `--username` | AD username | `--username admin@mydomain.local` |
| `--password` | AD password | `--password Secret123` |
| `--passive` | Run passive discovery | `--passive --iface "Wi-Fi"` |
| `--iface` | Network interface (optional, choose interactively if missing) | `--iface "Wi-Fi"` |
| `--timeout` | Passive discovery timeout in seconds (default: 180) | `--timeout 60` |

---

## 🔹 Example Runs and Outputs

### 🌐 Network Discovery

#### Real Run
Command:
```bash
python -m discovr.cli --scan-network 192.168.1.0/24
```
Output:
```text
[+] Scanning network: 192.168.1.0/24
[+] Running OS detection scan (requires admin privileges)
[+] 256 hosts scanned, processing results...

    [+] Found: 192.168.1.1 (router) | OS: Linux/Unix (guessed) | Ports: 80,443
    [+] Found: 192.168.1.10 (laptop01) | OS: Windows 10 Pro | Ports: 135,445
    [+] Found: 192.168.1.20 (server01) | OS: Linux 5.x kernel | Ports: 22,80,443

Discovered Assets (final report):
+---------------+-----------+-------------------+-----------+
| IP            | Hostname  | OS                | Ports     |
+---------------+-----------+-------------------+-----------+
| 192.168.1.1   | router    | Linux/Unix        | 80,443    |
| 192.168.1.10  | laptop01  | Windows 10 Pro    | 135,445   |
| 192.168.1.20  | server01  | Linux 5.x kernel  | 22,80,443 |
+---------------+-----------+-------------------+-----------+

[+] 3 active assets discovered out of 256 scanned hosts.
[+] Logs saved at logs/discovr_network_log_20250905_173000.log
```

#### Test Run
Command:
```bash
python -m tests.test_network
```
Output:
```text
[+] Scanning network: 192.168.1.0/24
[+] Running OS detection scan (requires admin privileges)
[+] 256 hosts scanned, processing results...

    [+] Found: 192.168.1.1 (router) | OS: Linux/Unix (guessed) | Ports: 80,443
    [+] Found: 192.168.1.10 (laptop01) | OS: Windows 10 Pro | Ports: 135,445
    [+] Found: 192.168.1.20 (server01) | OS: Linux 5.x kernel | Ports: 22,80,443

Discovered Assets (final report):
+---------------+-----------+-------------------+-----------+
| IP            | Hostname  | OS                | Ports     |
+---------------+-----------+-------------------+-----------+
| 192.168.1.1   | router    | Linux/Unix        | 80,443    |
| 192.168.1.10  | laptop01  | Windows 10 Pro    | 135,445   |
| 192.168.1.20  | server01  | Linux 5.x kernel  | 22,80,443 |
+---------------+-----------+-------------------+-----------+

[+] 3 active assets discovered out of 256 scanned hosts.
```

---

### ☁️ Cloud Discovery

#### Real Run (AWS)
Command:
```bash
python -m discovr.cli --cloud aws --profile default --region us-east-1
```
Output:
```text
[+] Discovering AWS assets...
    [+] AWS Instance: 54.12.34.56 (webserver01) | OS: Amazon Linux
    [+] AWS Instance: 10.0.0.12 (dbserver01) | OS: Windows Server 2019

Discovered Assets (final report):
+-------------+-------------+---------------------+-------+
| IP          | Hostname    | OS                  | Ports |
+-------------+-------------+---------------------+-------+
| 54.12.34.56 | webserver01 | Amazon Linux        | N/A   |
| 10.0.0.12   | dbserver01  | Windows Server 2019 | N/A   |
+-------------+-------------+---------------------+-------+

[+] 2 cloud assets discovered.
[+] Logs saved at logs/discovr_cloud_log_20250905_173100.log
```

#### Real Run (Azure)
Command:
```bash
python -m discovr.cli --cloud azure --subscription 12345678-abcd-1234-efgh-9876543210ab
```
Output:
```text
[+] Discovering AZURE assets...
    [+] Azure VM: 20.50.30.10 (azureweb01) | OS: Ubuntu 20.04
    [+] Azure VM: 10.0.0.5 (azuresql01) | OS: Windows Server 2022

Discovered Assets (final report):
+-------------+--------------+---------------------+-------+
| IP          | Hostname     | OS                  | Ports |
+-------------+--------------+---------------------+-------+
| 20.50.30.10 | azureweb01   | Ubuntu 20.04        | N/A   |
| 10.0.0.5    | azuresql01   | Windows Server 2022 | N/A   |
+-------------+--------------+---------------------+-------+

[+] 2 cloud assets discovered.
[+] Logs saved at logs/discovr_cloud_log_20250905_173150.log
```

#### Test Run
Command:
```bash
python -m tests.test_cloud
```
Output:
```text
[+] Running Cloud Discovery Tests
    [+] Simulated AWS VM: 54.12.34.56 (aws-web01) | OS: Amazon Linux
    [+] Simulated AWS VM: 10.0.0.12 (aws-db01) | OS: Windows Server 2019
    [+] Simulated AZURE VM: 20.50.30.10 (azure-app01) | OS: Ubuntu 20.04
    [+] Simulated AZURE VM: 10.0.0.5 (azure-sql01) | OS: Windows Server 2022

Discovered Assets (final report):
+-------------+--------------+---------------------+-------+
| IP          | Hostname     | OS                  | Ports |
+-------------+--------------+---------------------+-------+
| 54.12.34.56 | aws-web01    | Amazon Linux        | N/A   |
| 10.0.0.12   | aws-db01     | Windows Server 2019 | N/A   |
| 20.50.30.10 | azure-app01  | Ubuntu 20.04        | N/A   |
| 10.0.0.5    | azure-sql01  | Windows Server 2022 | N/A   |
+-------------+--------------+---------------------+-------+

[+] 4 cloud assets discovered (simulated).
```

---

### 🏢 Active Directory Discovery

#### Real Run
Command:
```bash
python -m discovr.cli --ad --domain mydomain.local --username admin@mydomain.local --password "Secret123"
```
Output:
```text
[+] Discovering Active Directory assets in mydomain.local
    [+] AD Computer: 192.168.1.25 (HR-PC01.mydomain.local) | OS: Windows 10 Pro
    [+] AD Computer: 192.168.1.30 (DB-SERVER01.mydomain.local) | OS: Windows Server 2019

Discovered Assets (final report):
+--------------+-----------------------------+--------------------+-------+
| IP           | Hostname                    | OS                 | Ports |
+--------------+-----------------------------+--------------------+-------+
| 192.168.1.25 | HR-PC01.mydomain.local      | Windows 10 Pro     | N/A   |
| 192.168.1.30 | DB-SERVER01.mydomain.local  | Windows Server 2019| N/A   |
+--------------+-----------------------------+--------------------+-------+

[+] 2 Active Directory assets discovered.
[+] Logs saved at logs/discovr_ad_log_20250905_173200.log
```

#### Test Run
Command:
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
+--------------+-----------------------------+--------------------+-------+
| IP           | Hostname                    | OS                 | Ports |
+--------------+-----------------------------+--------------------+-------+
| 192.168.1.25 | HR-PC01.mydomain.local      | Windows 10 Pro     | N/A   |
| 192.168.1.30 | DB-SERVER01.mydomain.local  | Windows Server 2019| N/A   |
| 192.168.1.40 | DEV-LAPTOP.mydomain.local   | Windows 11 Pro     | N/A   |
+--------------+-----------------------------+--------------------+-------+

[+] 3 Active Directory assets discovered (simulated).
```

---

### 📡 Passive Discovery

#### Real Run (Interactive, default 3 min)
Command:
```bash
python -m discovr.cli --passive
```
Output:
```text
[+] Available interfaces:
    [1] Ethernet (Intel(R) Ethernet Controller)
    [2] Wi-Fi (Intel(R) Wi-Fi 6 AX200)
    [3] Loopback Pseudo-Interface 1

Select interface by number: 2
[+] Starting passive discovery on interface: Wi-Fi
[+] Listening for ARP, DNS, DHCP, and mDNS traffic (auto-stop after 180 seconds or Ctrl+C)...

    [+] Passive Discovery Found: 192.168.1.50 (printer.local)
    [+] Passive Discovery Found: 192.168.1.60 (DHCP-aabbccddeeff)
    [+] Passive Discovery Found: N/A (chromecast._googlecast._tcp.local)

Discovered Assets (final report):
+-------------+-------------------------------+----------+-------+
| IP          | Hostname                      | OS       | Ports |
+-------------+-------------------------------+----------+-------+
| 192.168.1.50| printer.local                 | Unknown  | N/A   |
| 192.168.1.60| DHCP-aabbccddeeff             | Unknown  | N/A   |
| N/A         | chromecast._googlecast._tcp.local | Unknown | N/A |
+-------------+-------------------------------+----------+-------+

[+] 3 assets discovered during passive monitoring.
[+] Logs saved at logs/discovr_passive_log_20250905_173300.log
```

#### Real Run (Custom timeout, 1 min)
Command:
```bash
python -m discovr.cli --passive --iface "Wi-Fi" --timeout 60
```
Output:
```text
[+] Starting passive discovery on interface: Wi-Fi
[+] Listening for ARP, DNS, DHCP, and mDNS traffic (auto-stop after 60 seconds or Ctrl+C)...
```

#### Test Run
Command:
```bash
python -m tests.test_passive
```
Output:
```text
[+] Running Passive Discovery Test (Simulated)
    [+] Simulated Passive Asset: 192.168.1.50 (printer.local)
    [+] Simulated Passive Asset: 192.168.1.60 (iot-camera.local)

Discovered Assets (final report):
+-------------+-------------------+----------+-------+
| IP          | Hostname          | OS       | Ports |
+-------------+-------------------+----------+-------+
| 192.168.1.50| printer.local     | Unknown  | N/A   |
| 192.168.1.60| iot-camera.local  | Unknown  | N/A   |
+-------------+-------------------+----------+-------+

[+] 2 assets discovered during passive monitoring (simulated).
```

---

## 🔹 Platform Notes

- **Windows:** Run PowerShell as **Administrator**. Use friendly names like `"Wi-Fi"` or `"Ethernet"`.
- **Linux/Mac:** Run with `sudo`. Interfaces will look like `eth0`, `en0`, `wlan0`.
- **Timeout:** Default 3 minutes (`--timeout 180`). Override with `--timeout <seconds>`.

---
