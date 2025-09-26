A simple CLI tool to detect if your windows device is vulnerable to CVE-2017-0144 / MS17-010.
# Quick Installation
```
git clone https://github.com/RTKartograph/MS17-010-DetectorTool.git
cd MS17-010-DetectorTool
pip install -r requirements.txt
python3 .\main.py
```

Once successfully run, are able to choose two modes: Vulnerability Detection and Packet Detection.
## Packet Detection
This is a pretty simple detector any packet that passes through Port 445.
## Vulnerability Detection
By selecting this option, the program will check whether srv.sys (or srv2.sys) are up-to-date.
If the version of the driver is equal or above the standard, then the machine is not vulnerable.
Otherwise, if it detects your machine is not up to date, it will prompt you with the following:
### Making a firewall rule
A provisional measure in case you cannot afford to update your system.
### Patch Installation
The program will attempt to install the patch for you.

Have fun using it, and be safe!
