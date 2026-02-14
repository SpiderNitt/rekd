# R.E.K.D: Ransomware Entropy Kernel Detector
This repo can be used to check and flag ransomware presence in a system , with the help of ebpf technology and utilizes the idea of entropy for calculating whether ransomware or not 
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
