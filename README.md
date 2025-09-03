# Discovr - Asset Discovery Tool

Discovr is a lightweight asset discovery tool for **network and cloud environments**.  
It can actively scan networks, detect hosts, guess operating systems, list open ports, and discover assets in AWS and Azure.  
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
- **General**
  - Live discovery output per host/instance
  - Final summary in a tabular report
  - Logging of results and errors
  - Export to CSV and JSON (saved into `csv_report/` and `json_report/` folders)
- **Tests**
  - Test modules included for simulating multiple assets without running real scans

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

---

## 🔹 Example Runs

### Network Discovery (Full subnet scan with OS detection)
```bash
python -m discovr.cli --scan-network 192.168.1.0/24
```

### Network Discovery (Targeted scan with specific ports)
```bash
python -m discovr.cli --scan-network 192.168.1.0/24 --ports 22,80,443
```

### AWS Cloud Discovery
```bash
python -m discovr.cli --cloud aws --profile default --region us-east-1
```

### Azure Cloud Discovery
```bash
python -m discovr.cli --cloud azure --subscription 12345678-abcd-1234-efgh-9876543210ab
```

---

## 🔹 Example Output (Network Scan)

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

## 🔹 Example Output (AWS Cloud Discovery)

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

## 🔹 Example Output (Azure Cloud Discovery)

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

## 🔹 Test Modules

Test modules are provided to simulate assets without real scans.

### Network Discovery Test
```bash
python -m tests.test_network
```

### Cloud Discovery Test
```bash
python -m tests.test_cloud
```

### Example Test Output (Cloud)
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
