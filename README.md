
# 🛡️ Cybersecurity Internship Projects (Inlighn Tech)

This repository contains two Python-based cybersecurity projects developed during my internship with **Inlighn Tech**:

- 🔎 **Subdomain Enumeration Tool**  
- 🌐 **Network Scanner Tool**  

Both tools are designed to automate important reconnaissance and scanning tasks used in cybersecurity assessments.  

---

## 🚀 Project Overview

### 🔎 Subdomain Enumeration Tool
A Python script that automates the discovery of subdomains for a target domain.  
It helps identify hidden applications and services that may expand the attack surface.  

**Features:**
- Wordlist-based subdomain brute forcing (`subdomains.txt`)  
- Multi-threaded execution for speed  
- DNS resolution of live subdomains  
- Saves valid results into `discovered.txt`  

---

### 🌐 Network Scanner Tool
A Python script that scans and profiles devices on a local network.  
It identifies active hosts, resolves hostnames, detects OS, and scans open ports.  

**Features:**
- ARP-based host discovery  
- Reverse DNS for hostnames  
- OS detection using **nmap**  
- Port scanning of common TCP ports  
- Multi-threaded execution for efficiency  
- Results displayed in a formatted table  

---

## 📦 Requirements

Install the following Python modules before running the tools:

- `requests`  
- `threading`  
- `dnspython`  
- `scapy`  
- `socket`  
- `python-nmap`  
- `ipaddress`  
- `queue`  

👉 You can install them all at once (if you add a `requirements.txt` file):
```bash
pip install -r requirements.txt
````

---

## ▶️ Usage

### Run Subdomain Enumeration:

```bash
python Subdomain_Enumeration_Tool/subdomain_enum.py
```

### Run Network Scanner:

```bash
python Network_Scanner_Tool/network_scanner.py
```

---

## ⚙️ Installation

Clone the repository and navigate inside:

```bash
git clone https://github.com/ChinmayiSangaraju/CyberSecurity-Python-Projects-Inlighn-Tech-.git
cd CyberSecurity-Python-Projects-Inlighn-Tech-
```

Then install dependencies (either via `requirements.txt` or manually from the list above).

---

## 📄 Project Report

The complete report of both projects is available here:
👉 [Cybersecurity Internship Projects Report (PDF)](docs/Project_Report.pdf)

---

## 🚀 Future Improvements
* Add a GUI for user-friendly interaction
* Export results in multiple formats (CSV, JSON)

---

## ✍️ Author

**Chinmayi Sangaraju**
Internship at *Inlighn Tech*
