# Discovr - Asset Discovery Tool

Discovr is a lightweight asset discovery tool for **network, cloud, and Active Directory environments**.  
It can actively scan networks, detect hosts, guess operating systems, list open ports, discover assets in AWS and Azure, and query Active Directory for computer objects.  
Results can be exported to CSV/JSON and logs are automatically created.  

---

## 🔹 Features
- **Network Discovery**
  - Active scanning using Nmap
  - OS detection (requires admin/root privileges)
  - Port-specific scanning
- **Cloud Discovery**
  - AWS EC2 instance discovery (via boto3)
  - Azure VM discovery (via azure-identity + azure-mgmt)
  - Same save/export flow as Network Discovery (CSV/JSON prompt after run)
- **Active Directory Discovery**
  - Queries AD for computer objects
  - Collects Hostname, OS, and resolves IP if possible
  - Test module for simulating AD assets without a domain
- **General**
  - Live discovery output per host/instance
  - Final summary in a tabular report
  - Logging of results and errors
  - Export to CSV and JSON (saved into `csv_report/` and `json_report/` folders)
- **Tests**
  - Test modules included for simulating assets without running real scans

---

## 🔹 Usage

Run the tool with:

```bash
python -m discovr.cli [OPTIONS]
```

### Options
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

---

## 🔹 Example Outputs

### Network Discovery (Real Run)

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
[+] Total execution time: 19.32 seconds
[+] Logs saved at logs/discovr_log_20250904_010601.log

Do you want to save results? (yes/no): yes
Choose format (csv/json/both): both
[+] CSV saved: csv_report/discovr_csv_20250904_010601.csv
[+] JSON saved: json_report/discovr_json_20250904_010601.json
```

---

### AWS Cloud Discovery (Real Run)

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

[+] 2 active assets discovered.
[+] Total execution time: 3.12 seconds
[+] Logs saved at logs/discovr_log_20250904_123456.log

Do you want to save results? (yes/no): yes
Choose format (csv/json/both): both
[+] CSV saved: csv_report/discovr_csv_20250904_123456.csv
[+] JSON saved: json_report/discovr_json_20250904_123456.json
```

---

### Azure Cloud Discovery (Real Run)

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

[+] 2 active assets discovered.
[+] Total execution time: 4.01 seconds
[+] Logs saved at logs/discovr_log_20250904_124512.log

Do you want to save results? (yes/no): yes
Choose format (csv/json/both): json
[+] JSON saved: json_report/discovr_json_20250904_124512.json
```

---

### Active Directory Discovery (Real Run)

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
[+] Total execution time: 5.12 seconds
[+] Logs saved at logs/discovr_log_20250904_140245.log

Do you want to save results? (yes/no): yes
Choose format (csv/json/both): both
[+] CSV saved: csv_report/discovr_csv_20250904_140245.csv
[+] JSON saved: json_report/discovr_json_20250904_140245.json
```

---

## 🔹 Example Test Outputs

### Network Discovery Test
```bash
python -m tests.test_network
```

**Output:**
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

### Cloud Discovery Test
```bash
python -m tests.test_cloud
```

**Output:**
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
```

---

### Active Directory Discovery Test
```bash
python -m tests.test_active_directory
```

**Output:**
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

[+] 3 Active Directory assets discovered.
```
