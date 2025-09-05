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
| `--parallel` | Number of parallel workers for network scan (default: 1). Recommended: 5–20 for most subnets. | `--parallel 10` |
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
Discovered Assets (final report):
+---------------+-----------+-------------------+-----------+--------------+
| IP            | Hostname  | OS                | Ports     | Tag          |
+---------------+-----------+-------------------+-----------+--------------+
| 192.168.1.1   | router    | Linux/Unix        | 80,443    | [Network]    |
| 192.168.1.10  | laptop01  | Windows 10 Pro    | 135,445   | [Workstation]|
| 192.168.1.20  | server01  | Linux 5.x kernel  | 22,80,443 | [Server]     |
+---------------+-----------+-------------------+-----------+--------------+

[+] 3 active assets discovered out of 256 scanned hosts.
[+] Logs saved at logs/discovr_network_log_20250905_173000.log
```
#### Real Run (Parallel with 10 workers)
Command:
```bash
python -m discovr.cli --scan-network 192.168.1.0/24 --parallel 10
```
Output:
```text
[+] Scanning network: 192.168.1.0/24 with 10 parallel workers
[+] Running OS detection scan (requires admin privileges)
[+] 256 hosts scanned across 10 workers, processing results...

    [+] Found: 192.168.1.1 (router) | OS: Linux/Unix (guessed) | Ports: 80,443
    [+] Found: 192.168.1.10 (laptop01) | OS: Windows 10 Pro | Ports: 135,445
    [+] Found: 192.168.1.20 (server01) | OS: Linux 5.x kernel | Ports: 22,80,443

Discovered Assets (final report):
+---------------+-----------+-------------------+-----------+--------------+
| IP            | Hostname  | OS                | Ports     | Tag          |
+---------------+-----------+-------------------+-----------+--------------+
| 192.168.1.1   | router    | Linux/Unix        | 80,443    | [Network]    |
| 192.168.1.10  | laptop01  | Windows 10 Pro    | 135,445   | [Workstation]|
| 192.168.1.20  | server01  | Linux 5.x kernel  | 22,80,443 | [Server]     |
+---------------+-----------+-------------------+-----------+--------------+

[+] 3 active assets discovered out of 256 scanned hosts.
[+] Total execution time: 5.23 seconds (parallel scan)
[+] Logs saved at logs/discovr_network_log_20250905_180100.log
```

#### Test Run
Command:
```bash
python -m tests.test_network
```
Output:
```text
Discovered Assets (final report):
+---------------+-----------+-------------------+-----------+--------------+
| IP            | Hostname  | OS                | Ports     | Tag          |
+---------------+-----------+-------------------+-----------+--------------+
| 192.168.1.1   | router    | Linux/Unix        | 80,443    | [Network]    |
| 192.168.1.10  | laptop01  | Windows 10 Pro    | 135,445   | [Workstation]|
| 192.168.1.20  | server01  | Linux 5.x kernel  | 22,80,443 | [Server]     |
+---------------+-----------+-------------------+-----------+--------------+

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
Discovered Assets (final report):
+-------------+-------------+---------------------+-------+-------------+
| IP          | Hostname    | OS                  | Ports | Tag         |
+-------------+-------------+---------------------+-------+-------------+
| 54.12.34.56 | webserver01 | Amazon Linux        | N/A   | [Server]    |
| 10.0.0.12   | dbserver01  | Windows Server 2019 | N/A   | [Server]    |
+-------------+-------------+---------------------+-------+-------------+

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
Discovered Assets (final report):
+-------------+--------------+---------------------+-------+-------------+
| IP          | Hostname     | OS                  | Ports | Tag         |
+-------------+--------------+---------------------+-------+-------------+
| 20.50.30.10 | azureweb01   | Ubuntu 20.04        | N/A   | [Server]    |
| 10.0.0.5    | azuresql01   | Windows Server 2022 | N/A   | [Server]    |
+-------------+--------------+---------------------+-------+-------------+

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
Discovered Assets (final report):
+-------------+--------------+---------------------+-------+-------------+
| IP          | Hostname     | OS                  | Ports | Tag         |
+-------------+--------------+---------------------+-------+-------------+
| 54.12.34.56 | aws-web01    | Amazon Linux        | N/A   | [Server]    |
| 10.0.0.12   | aws-db01     | Windows Server 2019 | N/A   | [Server]    |
| 20.50.30.10 | azure-app01  | Ubuntu 20.04        | N/A   | [Server]    |
| 10.0.0.5    | azure-sql01  | Windows Server 2022 | N/A   | [Server]    |
+-------------+--------------+---------------------+-------+-------------+

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
Discovered Assets (final report):
+--------------+-----------------------------+--------------------+-------+--------------+
| IP           | Hostname                    | OS                 | Ports | Tag          |
+--------------+-----------------------------+--------------------+-------+--------------+
| 192.168.1.25 | HR-PC01.mydomain.local      | Windows 10 Pro     | N/A   | [Workstation]|
| 192.168.1.30 | DB-SERVER01.mydomain.local  | Windows Server 2019| N/A   | [Server]     |
+--------------+-----------------------------+--------------------+-------+--------------+

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
Discovered Assets (final report):
+--------------+-----------------------------+--------------------+-------+--------------+
| IP           | Hostname                    | OS                 | Ports | Tag          |
+--------------+-----------------------------+--------------------+-------+--------------+
| 192.168.1.25 | HR-PC01.mydomain.local      | Windows 10 Pro     | N/A   | [Workstation]|
| 192.168.1.30 | DB-SERVER01.mydomain.local  | Windows Server 2019| N/A   | [Server]     |
| 192.168.1.40 | DEV-LAPTOP.mydomain.local   | Windows 11 Pro     | N/A   | [Workstation]|
+--------------+-----------------------------+--------------------+-------+--------------+

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
Discovered Assets (final report):
+-------------+-------------------------------+----------+-------+---------+
| IP          | Hostname                      | OS       | Ports | Tag     |
+-------------+-------------------------------+----------+-------+---------+
| 192.168.1.50| printer.local                 | Unknown  | N/A   | [Printer]|
| 192.168.1.60| DHCP-aabbccddeeff             | Unknown  | N/A   | [IoT]    |
| N/A         | chromecast._googlecast._tcp.local | Unknown | N/A | [IoT]   |
+-------------+-------------------------------+----------+-------+---------+

[+] 3 assets discovered during passive monitoring.
[+] Logs saved at logs/discovr_passive_log_20250905_173300.log
```

#### Test Run
Command:
```bash
python -m tests.test_passive
```
Output:
```text
Discovered Assets (final report):
+-------------+-------------------+----------+-------+---------+
| IP          | Hostname          | OS       | Ports | Tag     |
+-------------+-------------------+----------+-------+---------+
| 192.168.1.50| printer.local     | Unknown  | N/A   | [Printer]|
| 192.168.1.60| iot-camera.local  | Unknown  | N/A   | [IoT]    |
+-------------+-------------------+----------+-------+---------+

[+] 2 assets discovered during passive monitoring (simulated).
```

---

## 🔹 Platform Notes

- **Windows:** Run PowerShell as **Administrator**. Use friendly names like `"Wi-Fi"` or `"Ethernet"`.
- **Linux/Mac:** Run with `sudo`. Interfaces will look like `eth0`, `en0`, `wlan0`.
- **Timeout:** Default 3 minutes (`--timeout 180`). Override with `--timeout <seconds>`.

---
