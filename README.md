<<<<<<< HEAD
# cognevance_network_vulnerability_assessment
Level 1 – Network Vulnerability Assessment (Cognevance Technologies)

## Lab setup
1. Install VirtualBox or VMware.
2. Create a **Host-only / internal network** (e.g. 192.168.56.0/24).
3. Install **Kali Linux** (attacker) and a target VM (Metasploitable 2, or an Ubuntu VM).
4. Install Nmap on Kali / your host: `sudo apt install nmap`.

## Run
```bash
python scanner.py 127.0.0.1                 # test on your own machine
python scanner.py 192.168.56.101            # lab VM
python scanner.py 192.168.56.0/24           # lab subnet
python scanner.py 127.0.0.1 --no-nmap       # built-in scanner (no Nmap needed)
```
Reports: `reports/vulnerability_report.md` and `reports/scan_results.json`.

## Manual Nmap commands (include output screenshots in `screenshots/`)
```bash
nmap -sn 192.168.56.0/24            # host discovery
nmap -sV -O 192.168.56.101          # services + OS
nmap -sC -sV -p- 192.168.56.101     # full port scan with default scripts
nmap --script vuln 192.168.56.101   # vulnerability scripts
```
## Safety
The script refuses non-private IPs. Test only systems you own or are authorized to test.
=======
# Cognevance Cyber Security & Ethical Hacking - Project Code

Three projects, each meant to be its own GitHub repo (`cognevance_projectName`):
1. `cognevance_network_vulnerability_assessment`
2. `cognevance_web_application_security_testing`
3. `cognevance_security_monitoring_incident_response`

## Run in VS Code
1. Unzip, then **File > Open Folder** on `cognevance_projects`. Install the *Python* extension.
2. Terminal: `pip install -r cognevance_web_application_security_testing/requirements.txt` (only project 2 needs packages).
3. Press **F5** (Run and Debug) and pick a configuration, e.g. *P3: SIEM pipeline*.
   Project 2: run *Vulnerable app*, then in a second terminal run *Web tester*.
4. Take screenshots of outputs into each project's `screenshots/` folder, then `git init`, commit and push each project folder as a separate repo.

Everything targets only localhost / private lab ranges / synthetic data.
# CyberCognevance
>>>>>>> f4b0a9c390f1698f6a7f8f7e859367a01e514b8d
