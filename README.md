# R.E.K.D: Ransomware Entropy Kernel Detector
* This project is an eBPF-based encrypted disk I/O scanner that monitors file write operations at the kernel level. 
* It hooks into the Linux `vfs\_write` system call to capture real-time write activity on regular files. 
* The system selectively samples large write buffers to avoid noise from small system writes like logs. 
* Captured data is analyzed in user space using Shannon entropy to detect potential encryption activity. 
* High-entropy data is treated as suspicious since encrypted ransomware outputs exhibit randomness. 
* The scanner maintains per-process statistics such as total written bytes and encrypted write ratio. 
* A configurable exclusion system allows trusted applications to be ignored during monitoring. 
* The tool supports both interactive monitoring mode and background daemon mode for continuous protection. 
* Suspicious processes are flagged based on encrypted write percentage and cumulative encrypted output. 
* Installation scripts automate deployment as a systemd service for persistent runtime monitoring. 


---
## 📦 Installation & Dependencies

### 1. System Requirements
This tool requires the BPF Compiler Collection (BCC). Install it using your package manager:
#### Ubuntu / Debian:
```bash
sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
```
### 2. Python Dependencies
This tool requires python dependencies for the dashboard UI(rich) and configuration parsing(pyyaml):
```bash
pip3 install rich pyyaml
```
---

### **Summary of Flags**


| Flag | Description |
| :--- | :--- |
| `--init-config` | Generates a default `exclusions.yaml` file and exits. |
| `--config [path]` | Loads exclusions from a specific YAML file (default: `./exclusions.yaml`). |
