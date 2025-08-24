import nmap

# Initialize the Nmap PortScanner object
nm = nmap.PortScanner()

# Target IP address (scanme.nmap.org = 45.33.32.156)
target = "45.33.32.156"

# Nmap scan options:
# -sV → Service version detection
# -sC → Run default Nmap scripts
options = "-sV -sC"

# Run the scan
print(f"[*] Scanning target: {target} with options: {options}\n")
nm.scan(target, arguments=options)

# Loop through all discovered hosts (usually just 1 in this case)
for host in nm.all_hosts():
    print("="*50)
    print(f"Host: {host} ({nm[host].hostname()})")
    print(f"State: {nm[host].state()}")
    print("="*50)

    # Loop through protocols (e.g., tcp/udp)
    for protocol in nm[host].all_protocols():
        print(f"\nProtocol: {protocol}")
        print("-"*50)

        # Get ports info for this protocol
        port_info = nm[host][protocol]

        # Loop through each port and print its state
        for port in sorted(port_info.keys()):
            state = port_info[port]['state']
            print(f"Port: {port}\tState: {state}")

print("\n[*] Scan completed successfully.")
