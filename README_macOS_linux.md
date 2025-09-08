# Discovr - macOS/linux Binary Usage Guide

This guide explains how to use the **macOS/linux binary (`discovr`)** for all Discovr features.  
It includes multiple ways to run, expected outputs, and special notes for interactive vs non-interactive usage.  

---

## 🔹 Running the Binary
1. Navigate to the folder containing the binary (usually `dist/` after PyInstaller build):
   ```bash
   cd ~/Documents/Discovr-Assest-Discovery/dist
   ```

2. Run the binary with desired arguments:
   ```bash
   ./discovr [OPTIONS]
   ```

3. On macOS/linux, you usually need **sudo** for raw socket operations and Nmap OS detection:
   ```bash
   sudo ./discovr [OPTIONS]
   ```

⚠️ **Important:** When using `sudo`, interactive prompts (like "Do you want to save results?") will not work.  
At that time, you **must** use the non-interactive options:  
- `--save yes` or `--save no`  
- `--format csv|json|both`  

---

## 🌐 Network Discovery

### Basic Run
```bash
sudo ./discovr --scan-network 192.168.1.0/24 --save no
```

### With Ports
```bash
sudo ./discovr --scan-network 192.168.1.0/24 --ports 22,80,443 --save no
```

### With Parallel
```bash
sudo ./discovr --scan-network 192.168.1.0/24 --parallel 10 --save no
```

### Auto-detect Subnet
```bash
sudo ./discovr --autoipaddr --parallel 5 --save yes --format both
```

Output:
```text
[+] Logs saved at /Users/demo/Documents/discovr_reports/logs/discovr_network_log_20250906_230500.log
[+] CSV saved: /Users/demo/Documents/discovr_reports/csv/discovr_network_20250906_230500.csv
[+] JSON saved: /Users/demo/Documents/discovr_reports/json/discovr_network_20250906_230500.json
```

---

## ☁️ Cloud Discovery

### AWS
```bash
./discovr --cloud aws --profile default --region us-east-1
```

### Azure
```bash
./discovr --cloud azure --subscription 12345678-abcd-1234-efgh-9876543210ab
```

### GCP
```bash
./discovr --cloud gcp --project my-gcp-project --zone us-central1-a
```

### Non-Interactive Save
```bash
./discovr --cloud aws --profile default --region us-east-1 --save yes --format csv
```
Output:
```text
[+] CSV saved: /Users/demo/Documents/discovr_reports/csv/discovr_cloud_20250906_231000.csv
```

---

## 🏢 Active Directory Discovery

### Run with Credentials
```bash
./discovr --ad --domain mydomain.local --username admin@mydomain.local --password "Secret123"
```

### Non-Interactive Save
```bash
./discovr --ad --domain mydomain.local --username admin@mydomain.local --password "Secret123" --save yes --format json
```
Output:
```text
[+] JSON saved: /Users/demo/Documents/discovr_reports/json/discovr_ad_20250906_231500.json
```

---

## 📡 Passive Discovery

### Interactive Interface Selection
```bash
sudo ./discovr --passive --save no
```

### Specify Interface with Timeout
```bash
sudo ./discovr --passive --iface "en0" --timeout 60 --save no
```

### Non-Interactive Save
```bash
sudo ./discovr --passive --iface "en0" --timeout 60 --save yes --format both
```
Output:
```text
[+] CSV saved: /Users/demo/Documents/discovr_reports/csv/discovr_passive_20250906_232000.csv
[+] JSON saved: /Users/demo/Documents/discovr_reports/json/discovr_passive_20250906_232000.json
```

---

## 📊 Where Reports Are Saved
All logs and exports are saved in the **Documents folder**:
```
/Users/<YourUsername>/Documents/discovr_reports/
    ├── logs/
    ├── csv/
    └── json/
```

---

## ✅ Notes
- Always run with **sudo** on macOS/linux for accurate results.  
- If using `sudo`, remember: interactive save prompts **will not work**. Use `--save` and `--format`.  
- Works on macOS Ventura and later.  
