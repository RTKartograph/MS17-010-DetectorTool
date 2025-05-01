from rich.console import Console
import subprocess

"""
I separated these just to keep the code clean.
(Ngl I just wanted to look more professional rather than keep everything in one file, that'd look gross too)
"""

console = Console()

RULE_NAME = "Block SMB Port 445"

def CheckRule():
    "Checks if the 'Block SMB Port 445' firewall rule exists."
    console.print(f"[[blue]*[/blue]] [yellow]Checking if rule exists...[/yellow]")
    check_rule = subprocess.run(args=['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name="{RULE_NAME}"'],
                                capture_output=True, text=True)
    return "No rule exists with specified criteria" not in check_rule.stdout

def CreateRule():
    "Creates the 'Block SMB Port 445' firewall rule."
    console.print(f"[[blue]*[/blue]] [yellow]Creating firewall rule...[/yellow]")
    create_rule = subprocess.run(args=['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name="{RULE_NAME}"', 'dir=in', 'action=block', 'protocol=TCP', 'localport=445'],
                                    capture_output=True, text=True)
    if create_rule.returncode == 0 and CheckRule():
        console.print(f"[[green]+[/green]] [green]Rule successfully created![/green]")
    else:
        console.print(f"[[bold red]*[/bold red]] [bold red]CRITICAL ERROR:[/bold red] Could not create firewall rule!\nMake sure you're running as administrator!")
        console.print(create_rule.stderr)

def DeleteRule():
    "Deletes the 'Block SMB Port 445' firewall rule."
    console.print(f"[[blue]*[/blue]] [yellow]Removing firewall rule...[/yellow]")
    remove_rule = subprocess.run(args=['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name="{RULE_NAME}"'],
                                capture_output=True, text=True)
    if remove_rule.returncode == 0:
        console.print(f"[[red]-[/red]] [red]Rule successfully removed![/red]")
    else:
        console.print(f"[[bold red]*[/bold red]] [bold red]CRITICAL ERROR:[/bold red] Could not remove firewall rule!\nMake sure you're running as administrator!")
        console.print(remove_rule.stderr)