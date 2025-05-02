from scapy.all import sniff
from rich.console import Console
from rich.table import Table
from FirewallRules import *
from FetchPatch import *
import sys
import win32api
import os
import platform

console = Console()

def clear():
    if os.name == 'nt':
        os.system('cls')
    else:
       print("Not a windows OS, closing.")
       sys.exit()
        

class EternalBlue_Counter_Tool:
    def __init__(self):
        clear() # Mainly used on debug

        console.print(f"[[bold blue]*[/bold blue]] Eternal[blue]blue[/blue]/Eternal[bright_magenta]romance[/bright_magenta] IDS Tool")
        console.print("#" * 35, style="bold blue")
        console.print("Options:", style="bold green")
        console.print("[bold green]1[/bold green][bold white]. [bold cornflower_blue]Packet Detection[/bold cornflower_blue]")
        console.print("[bold green]2[/bold green][bold white]. [bold slate_blue3]EternalBlue Vulnerability Detection[/bold slate_blue3]")
        console.print("#" * 35, style="bold blue")

        start_inpt = console.input("User Input: ")

        if start_inpt == "1":
            self.PacketDetect()
        elif start_inpt == "2":
            file, version_info = self.DriverLocator()
            self.CheckVulnerability(file, version_info)
        else:
            print("Not a correct input type.")

    def PacketDetect(self):
        console.print("SMB Detection has begun.", style="bold yellow")
        console.print("(Note: If you don't see anything being logged,\nit means you're receiving no request on [bold pale_turquoise4]PORT 445[/bold pale_turquoise4]\nEffectively, you're safe.)", style="bright_black")
        filter = "tcp port 445"
        sniff(prn=self.PacketLogging, filter=filter, store=False)
    
    def PacketLogging(self, packet):
        console.log(f"[bold blue] TCP Packet[/bold blue]: [bold yellow]{packet.summary()}")
    
    def DriverLocator(self):
        filepaths = [
            r"C:\Windows\System32\drivers\srv.sys",
            r"C:\Windows\System32\drivers\srv2.sys"
        ]

        for file in filepaths:
                if os.path.exists(file):
                    version_info = win32api.GetFileVersionInfo(file, '\\')
                    return file, version_info
        console.print("CRITICAL ERROR: Could not find srv.sys or srv2.sys. Stopping the program.", style="bold red")
        sys.exit()    

    def CheckVulnerability(self, file, version_info):
        table = Table(title="MS17-010 Diagnosis")
        table.add_column("Specification", style="red")
        table.add_column("Result", style="cyan")         
        ms = version_info['FileVersionMS']
        ls = version_info['FileVersionLS']
        version = (
            (ms >> 16) & 0xffff,
            ms & 0xffff,
            (ls >> 16) & 0xffff,
            ls & 0xffff
        )
        humanReadableVersion = '{}.{}.{}.{}'.format(*version)
        # print(f"Current Version: {humanReadableVersion}")

        win_ver = sys.getwindowsversion()
        # print(f"Current OS: {win_ver.major}, Minor {win_ver.minor}, Build {win_ver.build}")
        table.add_row("Driver Name:", os.path.basename(file))
        table.add_row("Driver Version:", humanReadableVersion)
        table.add_row("OS Version:", f"{win_ver.major}.{win_ver.minor}, Build {win_ver.build}")

        safe_versions = {
            (6, 0): (6002, 19743), # Windows Vista / Windows Server 2008
            (6, 1): (7601, 23689), # Windows 7
            (6, 3): (9600, 18604), # Windows 8.1 / Windows Server 2012 R2
            (10, 0): (10240, 17443), # Windows 10
            # (10, 0): (99999, 99999) # Debugging
        }

        os_key = (win_ver.major, win_ver.minor)

        if os_key not in safe_versions:
            console.print("OS not supported.", style="bright_black") # Why the FUCK is grey called bright black???
        
        safe_build = safe_versions[os_key]

        console.print(table)
        if version[2] < safe_build[0] or (version[2] == safe_build[0] and version[3] < safe_build[1]):
            console.print("System is [bold red]VULNERABLE[/bold red] to MS17-010.")
            self.SafetyPrompt()
        else:
            console.print("System is [bold green]PATCHED[/bold green] against MS17-010.")
    
    def SafetyPrompt(self):
        console.print("=" * 30, style="purple")
        console.print("Options to counteract MS17-010:")
        console.print("[bold green]1[/bold green]. Make a firewall rule [bold yellow](RECOMMENDED)[/bold yellow]")
        console.print("[bold green]2[/bold green]. Install the patch [bold red](RISKY)[/bold red]")
        console.print("[bold green]3[/bold green]. Exit [bold red](NOT RECOMMENDED)[/bold red]")
        snd_inp = console.input("[underline]User Input:[/underline] ")

        if snd_inp == "1":

            if CheckRule():
                console.print(f"Firewall rule already exists: {RULE_NAME}!", style="underline cyan")
                a = console.input("[yellow]Do you want to remove it? (y/n): [/yellow]").strip().lower()
                if a == "y":
                    DeleteRule()
                else:
                    console.print("[[blue]*[/blue]] Keeping existing firewall rule.")
            else:
                CreateRule()

        if snd_inp == "2":
            win_ver = sys.getwindowsversion()
            arch = platform.machine().lower()
            arch = "x64" if "64" else "x86"
            print(GetPatchURL((win_ver.major, win_ver.minor, win_ver.build), win_ver.build, arch))
            """if filename:
                RunPatch(filename)"""
        else:
            print("Exiting the program...")
            sys.exit()

if __name__ == '__main__':
    EternalBlue_Counter_Tool()