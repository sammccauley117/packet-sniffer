from scapy.all import *
import sys, socket, os

FILE = 'data.csv'
MY_IP = 'YOUR_LOCAL_IP'
LOG_COUNT = 1000
LABEL = 1
MIN_PACKETS = 3

def process_packets(packets):
    # 1) Create dictionaries of flows
    flows = {}
    for packet in packets:
        # a) Get basic IP info (source, destination, protocol)
        src = packet.sprintf('%IP.src%')
        dst = packet.sprintf('%IP.dst%')
        proto = packet.sprintf('%IP.proto%')

        # b) Get source port and destination port (throw away if packet isn't TCP/UDP or a weird port)
        if proto == 'tcp':
            sport = packet.sprintf('%TCP.sport%')
            dport = packet.sprintf('%TCP.dport%')
        elif proto == 'udp':
            sport = packet.sprintf('%UDP.sport%')
            dport = packet.sprintf('%UDP.dport%')
        else:
            continue
        if sport == 'netbios_ns' or dport == 'netbios_ns': continue
        if sport == 'ssdp' or dport == 'ssdp': continue

        # c) Append to flow dictionaries
        key = (src, dst, sport, dport, proto) # Key is packet info tuple
        if key in flows: # Entry already exists, append
            flows[key].append(packet)
        else: # Create new entry
            flows[key] = [packet]

    # 2) Cleanup flows with insufficient packets
    for key, packets in flows.items():
        if len(packets) < MIN_PACKETS:
            del flows[key]

    # 3) Get the features of each flow
    for flow in flows.values():
        packet = flow[0]
        # a) Get static features (just need to look at one packet in flow)
        proto = 0 if packet.sprintf('%IP.proto%')=='tcp' else 1 # Protocol: TCP = 0, UDP = 1
        sr = 0 if packet.sprintf('%IP.src%') == MY_IP else 1 # Sent/Received: sent = 0, received = 1
        ip_flags = 0 if packet.sprintf('%IP.flags%') != 'DF' else 1 # Flags: empty = 0, DF = 1
        sport = packet.sprintf('%UDP.sport%') if proto else packet.sprintf('%TCP.sport%')
        dport = packet.sprintf('%UDP.dport%') if proto else packet.sprintf('%TCP.dport%')
        tcp_flags_str = '' if proto else packet.sprintf('%TCP.flags%')
        packet_count = len(flow)
        if sport == 'https' or sport == 'http': sport = -1
        if dport == 'https' or dport == 'http': dport = -1
        # Convert the tcp_flag_str to an integer based off of ascii values
        tcp_flags = 0
        if tcp_flags_str != '':
            for c in tcp_flags_str:
                tcp_flags += ord(c)


        # b) Compute average and total data length
        total_len = 0
        for packet in flow:
            total_len += int(packet.sprintf('%IP.len%'))
        avg_len = total_len / packet_count

        # c) Build and commit the CSV data
        data = [str(packet_count), str(total_len), str(avg_len), str(proto), str(sr),
                str(ip_flags), str(tcp_flags), str(sport), str(dport), str(LABEL)]
        with open(FILE, 'a') as file:
            file.write(','.join(data)+'\n')

if __name__ == '__main__':
    packets = sniff(count=LOG_COUNT)
    process_packets(packets)

# Potential Features:
#   Ethernet
#       %Ether.dst%: destination MAC address
#       %Ether.src%: source MAC address
#       %Ether.type%: transmission protocol for the next layer (IPv4, IPv6, etc.)
#   IP
#       %IP.version%: protocol version (i.e. 4 means IPv4)
#       %IP.ihl%: IP header length
#       %IP.tos%: type of service (lowdelay, throughput, reliability, lowcost)
#    *  %IP.len%: length of IP packet (data)
#    *  %IP.flags%: whether or not the packet can be fragmented
#       %IP.frag%: fragment number
#       %IP.ttl%: time to live
#    *  %IP.proto%: protocol (ICMP, TCP, UDP, etc.)
#       %IP.src%: IP source address
#       %IP.dest%: IP destination address
#   TCP
#    *  %TCP.sport%: source port
#    *  %TCP.dport%: destination port
#       %TCP.seq%: sequence number (index)
#       %TCP.ack%: acknowledgement number
#       %TCP.dataofs%: data offset
#    *  %TCP.flags%: control flags (sync., ack., finished, urgent, etc.)
#       %TCP.window%: window size (how much data can be sent before an ack is needed)
#       %TCP.chksum%: checksum for data verification
#       %TCP.urgptr%: urgent pointer, used with urgent flag
#       %TCP.options%: additional control options
#   UDP
#    *  %UDP.sport%: source port
#    *  %UDP.dport%: destination port
#       %UDP.len%: length of data
#       %UDP.chksum%: checksum for data verification
