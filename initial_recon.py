#!/usr/bin/env python3

import subprocess
import sys
import os
from datetime import datetime

def usage():
    print(f"Usage: {sys.argv[0]} <target-ip>")
    sys.exit(1)
  
def run_command(cmd):
    """Run a shell command and return the output."""
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error running command: {e}"

def parse_open_ports(nmap_output):
    """Extract up to 5 open ports from grepable nmap output."""
    ports = set()
    for line in nmap_output.splitlines():
        if "Ports:" in line:
            parts = line.split("Ports:")[1]
            for port_entry in parts.split(","):
                if "open" in port_entry:
                    port = port_entry.strip().split("/")[0]
                    ports.add(int(port))
                if len(ports) >=5:
                    break
    return sorted(ports)

def main():
    # the num of args have to be 2, 0th is filename(hidden), 1st is IP address
    if len(sys.argv) != 2: 
        usage()

    # setting the target IP, timestamp, directory of output, making the dir, and output filename 
    target = sys.argv[1]
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    loot_dir = "./loot"
    os.makedirs(loot_dir, exist_ok=True)
    output_file = os.path.join(loot_dir, f"external-{target}-{timestamp}.txt")
    
    # with loop to write into output_file. set w for write. 
    with open(output_file, "w") as f:
        # using f to write output to the file
        f.write(f"[*] External Recon on {target} at {timestamp}\n")

        # nmap scan command as a fstring to pass to run_command and then writes the output to f
        f.write(f"[*] Running NMAP scan...\n")
        nmap_cmd = f"nmap -Pn -sS -n -T4 {target} -oG -"
        nmap_output = run_command(nmap_cmd)
        f.write(nmap_output + "\n")

        # parse open ports found in nmap passing the nmap output to the parse_open_ports()
        ports = parse_open_ports(nmap_output)
        f.write(f"\n[*] Top Open Ports: {ports}\n")

        # Follow-up based on ports
        for port in ports:
            f.write(f"\n--- Port {port} Analysis ---\n")
            if port in [80, 8080]:
                f.write("[*] Running HTTP checks...\n")
                robots = run_command(f"curl -s http://{target}:{port}/robots.txt")
                f.write(f"\nrobots.txt:\n{robots}\n")
                
                whatweb = run_command(f"whatweb http://{target}:{port}")
                f.write(f"\nWhatWeb:\n{whatweb}\n")

                ffuf = run_command(
                    f"ffuf -u http://{target}:{port}/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c -v -mc 200-403 -s")
                f.write(f"\nFFUF Results:\n{ffuf}\n")
            elif port == 443:
                f.write("[*] Running HTTPS checks...\n")
                robots = run_command(f"curl -sk https://{target}/robots.txt")
                f.write(f"\nrobots.txt:\n{robots}\n")
                ssl = run_command(f"echo | openssl s_client -connect {target}:443 -servername {target}")
                f.write(f"\nSSL Info:\n{ssl}\n")
                ffuf = run_command(
                        f"ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c -v -mc 200-403 -s")
                f.write(f"\nFFUF Results:\n{ffuf}\n")
                
            elif port == 22:
                ssh = run_command(f"nc -vz {target} 22")
                f.write(f"[*] SSH Banner:\n{ssh}\n")

            elif port == 21:
                ftp = run_command(f"echo 'QUIT' | nc {target} 21")
                f.write(f"[*] FTP Banner:\n{ftp}\n")
            
            elif port == 3306:
                mysql = run_command(f"timeout 5 bash -c 'cat < /dev/null > /dev/tcp/{target}/3306'")
                f.write(f"[*] MySQL Port Response:\n{mysql or 'Open'}\n")

            else:
                f.write(f"[*] No custom recon defined for port {port}\n")
        
        f.write("\n[*] External Recon Complete.\n")

if __name__ == "__main__":
    main()
