import subprocess

def block_ip(ip: str):
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[IPTABLES] Blocked IP: {ip}")
    except subprocess.CalledProcessError:
        print(f"[IPTABLES] Failed to block IP: {ip}")

def unblock_ip(ip: str):
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[IPTABLES] Unblocked IP: {ip}")
    except subprocess.CalledProcessError:
        print(f"[IPTABLES] Failed to unblock IP: {ip}")