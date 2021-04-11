#!/usr/bin/env python
import scapy.all as scapy
import optparse

def argument():
    parser= optparse.OptionParser()
    parser.add_option("-r", "--range" , dest="range", help="Enter the Range of the network")
    (option,argument) = parser.parse_args()
    return str(option.range)

def scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    Ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = Ether/arp_packet
    #packet.show()
    answered_pack = scapy.srp(packet, timeout=1, verbose=False)[0]
    client_list = [] #now create a list to store ip and mac of devices in network

    for i in answered_pack:
        client_dict={"ip":i[1].psrc, "mac":i[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def show(list):
    print("     IP\t\t\tMAC\n--------------------------------")
    for i in list:
        print(i["ip"] + "\t" + i["mac"])

def call():
    arg = argument()
    show(scan(arg))

call()