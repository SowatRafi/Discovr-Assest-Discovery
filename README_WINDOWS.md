# Discovr - Windows Binary Usage Guide

This guide shows how to use the **Windows binary (`discovr.exe`)** for all features of Discovr.  
It covers multiple ways to run each feature, how to execute it in PowerShell, and the expected outputs.  

---

## 🔹 Running the Binary
1. Navigate to the folder containing the binary (usually `dist\` after PyInstaller build):
   ```powershell
   cd "C:\Users\<YourUsername>\Documents\Discovr-Assest-Discovery\dist"
   ```

2. Run the binary with desired arguments:
   ```powershell
   .\discovr.exe [OPTIONS]
   ```

3. Make sure to run as **Administrator** (required for OS detection and raw socket access):
   ```powershell
   Start-Process .\discovr.exe -ArgumentList "--scan-network 192.168.1.0/24" -Verb runAs
   ```

---

## 🌐 Network Discovery

### Basic Run
```powershell
.\discovr.exe --scan-network 192.168.1.0/24
```

### With Ports
```powershell
.\discovr.exe --scan-network 192.168.1.0/24 --ports 22,80,443
```

### With Parallel
```powershell
.\discovr.exe --scan-network 192.168.1.0/24 --parallel 10
```

### Auto-detect Subnet
```powershell
.\discovr.exe --autoipaddr --parallel 5
```

### Non-Interactive Save
```powershell
.\discovr.exe --scan-network 192.168.1.0/24 --save yes --format both
```

Output:
```text
[+] CSV saved: C:\Users\demo\Documents\discovr_reports\csv\discovr_network_20250906_230500.csv
[+] JSON saved: C:\Users\demo\Documents\discovr_reports\json\discovr_network_20250906_230500.json
```

---

## ☁️ Cloud Discovery

### AWS
```powershell
.\discovr.exe --cloud aws --profile default --region us-east-1
```

### Azure
```powershell
.\discovr.exe --cloud azure --subscription 12345678-abcd-1234-efgh-9876543210ab
```

### GCP
```powershell
.\discovr.exe --cloud gcp --project my-gcp-project --zone us-central1-a
```

### Non-Interactive Save
```powershell
.\discovr.exe --cloud aws --profile default --region us-east-1 --save yes --format csv
```

Output:
```text
[+] CSV saved: C:\Users\demo\Documents\discovr_reports\csv\discovr_cloud_20250906_231000.csv
```

---

## 🏢 Active Directory Discovery

### Run with Credentials
```powershell
.\discovr.exe --ad --domain mydomain.local --username admin@mydomain.local --password "Secret123"
```

### Non-Interactive Save
```powershell
.\discovr.exe --ad --domain mydomain.local --username admin@mydomain.local --password "Secret123" --save yes --format json
```

Output:
```text
[+] JSON saved: C:\Users\demo\Documents\discovr_reports\json\discovr_ad_20250906_231500.json
```

---

## 📡 Passive Discovery

### Interactive Interface Selection
```powershell
.\discovr.exe --passive
```

### Specify Interface with Timeout
```powershell
.\discovr.exe --passive --iface "Ethernet" --timeout 60
```

### Non-Interactive Save
```powershell
.\discovr.exe --passive --iface "Ethernet" --timeout 60 --save yes --format both
```

Output:
```text
[+] CSV saved: C:\Users\demo\Documents\discovr_reports\csv\discovr_passive_20250906_232000.csv
[+] JSON saved: C:\Users\demo\Documents\discovr_reports\json\discovr_passive_20250906_232000.json
```

---

## 📊 Where Reports Are Saved
All logs and exports are saved in the **Documents folder**:
```
C:\Users\<YourUsername>\Documents\discovr_reports\
    ├── logs\
    ├── csv\
    └── json\
```

---

## ✅ Notes
- Always run as Administrator for accurate results.  
- Use `--save` and `--format` to avoid interactive prompts (useful in scripts).  
- Works on Windows 10/11 with PowerShell or Command Prompt.  
