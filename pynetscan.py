#!/usr/bin/env python

import scapy.all as scapy
import argparse


def banner():
    print("""\u001b[33m
     @@@@@@@  @@@ @@@ @@@  @@@ @@@@@@@@ @@@@@@@       @@@@@@  @@@@@@@  @@@@@@  @@@  @@@
     @@!  @@@ @@! !@@ @@!@!@@@ @@!        @@!        !@@     !@@      @@!  @@@ @@!@!@@@
     @!@@!@!   !@!@!  @!@@!!@! @!!!:!     @!!         !@@!!  !@!      @!@!@!@! @!@@!!@!
     !!:        !!:   !!:  !!! !!:        !!:            !:! :!!      !!:  !!! !!:  !!!
      :         .:    ::    :  : :: :::    :         ::.: :   :: :: :  :   : : ::    : 

    \u001b[0m""")
    print("\u001b[31m\t\t\t\tNetwork Scanner coded by pyroot\u001b[0m\n")


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target Ip/Ip range")
    option = parser.parse_args()
    if not option.target:
        print("Target IP not found ")
        print("[-] Please enter the target IP or target IP range")
        print("Use --help for more Info")
        return
    return option


def scan(ip):
    # creating a arp packet
    arp_packet = scapy.ARP(pdst=ip)
    # creating an ethernet packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # attaching the arp packet with the ether packet
    arp_request_broadcast = broadcast / arp_packet
    # srp gives back a list of two elements 1)answered and 2) unanswered packets ,answered packets
    # consists of two elements 1)packet sent and 2) answer , here we are taking the packet sent from
    # the answered_list variable
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


banner()
try:
    options = get_arguments()
    scan_result = scan(options.target)
    print_result(scan_result)
except AttributeError:
    pass
