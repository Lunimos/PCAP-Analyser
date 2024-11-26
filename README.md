# PCAP-Analyser
Description of PCAP Analysis Script
The script provides a user-friendly interface for analyzing PCAP (Packet Capture) files. It is designed to perform several tasks related to network traffic analysis:

Features:
Packet Counting and Timestamp Analysis:

Counts the total number of packets and categorizes them by protocol (TCP, UDP, ICMP, IGMP).
Extracts and displays the first and last timestamps for each protocol.
Calculates the mean packet length for each protocol.
Email Extraction:

Extracts destination email addresses from packet data (SMTP, IMAP, and POP protocols).
Uses regular expressions to identify and collect email addresses.
IP Pair Mapping:

Analyzes source and destination IP address pairs.
Displays unique pairs and counts occurrences for each pair.
User Interface:
The script includes a menu-driven interface:
Option to analyze a PCAP file or quit the program.
Once a file is analyzed, users can:
View packet statistics and timestamps.
Extract email addresses.
Analyze IP address pairs.
Process another file or return to the main menu.
Libraries Used:
dpkt: For parsing PCAP files.
socket: To convert raw IP addresses into a human-readable format.
re: For extracting email addresses using regular expressions.
datetime: For timestamp formatting.
collections.defaultdict: For efficient counting of IP pairs.
Error Handling:
Handles file I/O errors gracefully, prompting the user for a valid file.
Includes a mechanism to display helpful error messages and guide the user back to valid inputs.
Intended Use Case:
This script is useful for cybersecurity analysts, network administrators, and researchers working with packet capture files to investigate network activity, extract specific information, or perform traffic analysis.
