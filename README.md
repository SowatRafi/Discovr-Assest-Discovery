# Discovr - Asset Discovery Tool

Discovr is a lightweight asset discovery tool for **network environments**.  
It can actively scan networks, detect hosts, guess operating systems, list open ports, and export results to CSV/JSON.  

---

## 🔹 Features
- Network scanning using Nmap
- OS detection (requires admin/root privileges)
- Port-specific scanning
- Live discovery output per host
- Final summary in a tabular report
- Logging of results and errors
- Export to CSV and JSON (saved into `csv_report/` and `json_report/` folders)
- Test module included for simulating multiple assets without running real scans

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

---

## 🔹 Example Runs

### Full subnet scan with OS detection
```bash
python -m discovr.cli --scan-network 192.168.1.0/24
```

### Targeted scan with specific ports
```bash
python -m discovr.cli --scan-network 192.168.1.0/24 --ports 22,80,443
```

---

## 🔹 Example Output

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

## 🔹 Test Module for Network Discovery

A test module is included to **simulate multiple assets** without running real Nmap scans.

### Run the test module:
```bash
python -m tests.test_network
```

### Example Test Output:
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
```
