IDS -

A simple network intrusion detection system built with Python and Scapy.

The program monitors TCP traffic and tracks destination ports by source IP address. If an IP accesses a configurable number of different ports within a time window, the program generates an alert and saves it to a log file.

Features

- Capture TCP packets using Scapy.
- Extract source IP addresses and destination ports.
- Detect activity involving multiple destination ports.
- Generate alerts and save them to "alertas.log".

Requirements

- Python
- Scapy
- Npcap (Windows)

Install the Python dependency:

py -m pip install -r requirements.txt

Usage

Run the program from the project directory:

py ids.py

Depending on the Windows configuration, packet capture may require administrator privileges.

Configuration

The detection threshold and time window can be adjusted in "ids.py":

- "limite_puertos": number of distinct destination ports required to trigger an alert.
- "ventanas_tiempo": time window in seconds.

Limitations

This is a basic detector based on a port-count threshold. It can generate false positives and does not identify every type of network intrusion.

Use it only on networks you own or are authorized to monitor.