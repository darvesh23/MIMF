#!/usr/bin/env python
import subprocess
import optparse
import re

def parse():
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface", dest = "interface" , help = "Enter the interface name")
    parser.add_option("-m","--mac", dest = "mac_add" , help = "Enter the new mac address")
    return parser.parse_args()

def new_mac(interface,mac):
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", mac])
    subprocess.call(["ifconfig", interface, "up"])

def exp(interface):
    ifconfig_output = subprocess.check_output(["ifconfig",interface])
    new_add =re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",ifconfig_output)
    if new_add:
        return str(new_add.group(0))

def validation(mac,expr):
    if expr == mac:
        print("[+] Mac Address Changed To : " + expr)
    else:
        print("[-] Please Enter Correct args")

def run_fun():
    (option, argument) = parse()
    new_mac(option.interface,option.mac_add)
    expr = exp(option.interface)
    validation(option.mac_add,expr)

run_fun()