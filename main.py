from scapy.all import packet, sniff
import sys
import win32api

class EternalBlue_Counter_Tool:
    def __init__(self):
        start_inpt = str(input("Make your selection\n1. Packet Detection\n2. EternalBlue Vuln. Detection\nUser Input: "))

        if start_inpt == "1":
            self.PacketDetect()
        elif start_inpt == "2":
            self.Check_Vuln()
        else:
            print("Not a correct input type.")

    def PacketDetect(self):
        print("\nStarting SMB sniffing session...")
        sniff(prn=lambda x: x.summary(), filter="tcp port 445", store=False)

    def Check_Vuln(self):
        try:
            with open(r"C:\Windows\System32\drivers\srv.sys", 'rb') as f:
                print("srv.sys located. Trying for srv2.sys ...")
        except FileNotFoundError:
            try:
                with open(r"C:\Windows\System32\drivers\srv2.sys", 'rb') as f:
                    print("srv2.sys located.")
            except FileNotFoundError:
                print("Could not find neither, cannot continue.")
                sys.exit()         

        info = win32api.GetFileVersionInfo(f.name, "\\")
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        version = (
            (ms >> 16) & 0xffff,
            ms & 0xffff,
            (ls >> 16) & 0xffff,
            ls & 0xffff
        )
        humanReadableVersion = '{}.{}.{}.{}'.format(*version)
        print(f"Current Version: {humanReadableVersion}")

        win_ver = sys.getwindowsversion()
        print(f"Current OS: {win_ver.major}, Minor {win_ver.minor}, Build {win_ver.build}")

        safe_versions = {
            (6, 1): (7601, 23689), # Windows 7
            (6, 0): (6002, 19743), # Windows Vista / Windows Server 2008
            (6, 3): (9600, 18604), # Windows 8.1 / Windows Server 2012 R2
            (10, 0): (10240, 17443), # Windows 10
        }

        os_key = (win_ver.major, win_ver.minor)

        if os_key not in safe_versions:
            print("OS not supported.")
        
        safe_build = safe_versions[os_key]

        if version[2] < safe_build[0] or (version[2] == safe_build[0] and version[3] < safe_build[1]):
            print("System is VULNERABLE to MS17-010.")
        else:
            print("System is PATCHED against MS17-010.")
        

if __name__ == '__main__':
    EternalBlue_Counter_Tool()