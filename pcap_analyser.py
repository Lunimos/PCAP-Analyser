#!/usr/bin/env python
"""
Elliot Ross-Hammond
Scripting for Cyber Security
"""
import sys
import re
import socket
from datetime import datetime
from collections import defaultdict
import time
import dpkt


def wrong_data():
    """Function for wrong inputs."""
    print("""
    ----------------------------
    | Incorrect Option         |
    |                          |
    | Please Try Again         |
    |                          |
    | Watch For Typo's         |
    ----------------------------
    """)


def main():
    """Main function for calling the first menu."""
    usermenu()


def usermenu():
    """First menu to analyze file or quit."""
    print("""
          --------------
         | MAIN----MENU |       
          -------------- 
    """)

    print("""
    Press A To Analyse A File
    Press Q To Quit The Program
    Please Select An Option""")
    userinput = input(" ")

    if userinput.lower() == "a":
        return menu_2()
    elif userinput.lower() == "q":
        print("Goodbye..")
        time.sleep(1)
        sys.exit()
    else:
        wrong_data()
        usermenu()


def menu_2():
    """Menu for opening and parsing a pcap file."""
    userinput = input("Please enter a file name: ")

    try:
        with open(userinput, "rb") as log:
            pcap = dpkt.pcap.Reader(log)
            packet_store = list(pcap)

        print(f"The packets were stored successfully from {userinput}")
        time.sleep(1)
    except IOError:
        wrong_data()
        menu_2()

    userinput = input("""
1. Extract Packet Data
2. Extract Emails and URLs
3. Extract Source and Destination IP Pairs
4. Input Another File

Q. Press Q for main menu
""")

    if userinput == "1":
        packet_counter(packet_store)
    elif userinput == "2":
        email_url(packet_store)
    elif userinput == "3":
        ip_pairs(packet_store)
    elif userinput == "4":
        menu_2()
    elif userinput.lower() == "q":
        usermenu()


def packet_counter(packet_store):
    """Counts packets and extracts timestamps."""
    protocols = defaultdict(lambda: {"count": 0, "timestamps": []})
    for ts, buf in packet_store:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            proto = ip.p
            protocols[proto]["count"] += 1
            protocols[proto]["timestamps"].append(ts)
        except Exception:
            continue

    for proto, data in protocols.items():
        first_ts = datetime.utcfromtimestamp(min(data["timestamps"])) if data["timestamps"] else None
        last_ts = datetime.utcfromtimestamp(max(data["timestamps"])) if data["timestamps"] else None
        print(f"Protocol {proto}: {data['count']} packets, First: {first_ts}, Last: {last_ts}")


def email_url(packet_store):
    """Extract emails and URLs from packet payloads."""
    email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    url_regex = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),])+'

    emails = set()
    urls = set()

    for _, buf in packet_store:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data

            payload = tcp.data.decode(errors="ignore")
            emails.update(re.findall(email_regex, payload))
            urls.update(re.findall(url_regex, payload))
        except Exception:
            continue

    print(f"Emails Found: {emails}")
    print(f"URLs Found: {urls}")


def ip_pairs(packet_store):
    """Extract and count source and destination IP pairs."""
    ip_counts = defaultdict(int)

    for _, buf in packet_store:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            ip_counts[(src, dst)] += 1
        except Exception:
            continue

    for (src, dst), count in ip_counts.items():
        print(f"Source: {src}, Destination: {dst}, Count: {count}")


if __name__ == "__main__":
    main()
