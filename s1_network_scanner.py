#!/usr/bin/env python3

import scapy.all as scapy
from argparse import ArgumentParser, Namespace
from re import search
from typing import Union


def get_arguments() -> Namespace:
    parser: ArgumentParser = ArgumentParser()
    parser.add_argument("-r", "--range", dest="ip_range", help="set an ip range to scan (Usage: x.x.x.x/(1-32))", type=str, required=True)
    args: Namespace = parser.parse_args()
    return args


def scan(ip: str) -> list:
    arp_request: scapy.ARP = scapy.ARP(pdst=ip)
    broadcast: scapy.Ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast: Union[scapy.Ether, scapy.ARP] = broadcast/arp_request
    ans: list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list: list = []
    for element in ans:
        client_dict: dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list
    

def print_result(results_list: list) -> None:
    print("IP\t\tMAC Address\n----------------------------------")
    for client in results_list:
        print(client["ip"] + "\t" + client["mac"])


def main():
    args: Namespace = get_arguments()

    if search(r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/(3[0-2]|[1-2]?\d)$', args.ip_range):
        scan_result: list = scan(args.ip_range)
        print_result(scan_result)
    else:
        print('[-] Invalid argument found! Check "--help" for more context!')
    

if __name__ == "__main__":
    main()
