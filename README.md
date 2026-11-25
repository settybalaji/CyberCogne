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
