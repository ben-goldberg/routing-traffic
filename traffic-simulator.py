# Author: Ben Goldberg
# Adapted from https://github.com/ben-goldberg/userspace-routing
# Written by Ben Goldberg & Louis Brann
from scapy.all import *
import socket
import sys
import subprocess
from util import *

# TODO
# -------------
# Test current functionality
# Make Router class to encapsulate this file
# Instead of calling main, call my_router.setup & my_router.start
# Constructor takes config file, gets neceassary info for .setup function
# router has 4 phases for traffic simulation, provides API for seeing current
#   phase and for switching between phases: my_router.get_phase(), .set_phase()
#   this may require 2 processes: 1 to run routing, one to listen for phase
#   change calls and notify main process
# Provide throughput metrics
# Make this run faster?
# --------------


class RoutingTable:
    class RoutingTableEntry:
        def __init__(self, param_list, metric=1):
            self.dest = param_list[0]
            self.netmask = param_list[1]
            self.gateway = param_list[2]
            self.gateway_mac = param_list[3]
            self.interface = param_list[4]
            self.local_mac = param_list[5]
            self.metric = metric
        def __repr__(self):
            return "dest: " + str(self.dest) \
                + "\tnetmask: " + str(self.netmask) \
                + "\tgateway: " + str(self.gateway) \
                + "\tgateway_mac: " + str(self.gateway_mac) \
                + "\tinterface: " + str(self.interface) \
                + "\tlocal_mac: " + str(self.local_mac) \
                + "\tmetric: " + str(self.metric) \
                + "]"

    def __init__(self):
        self.table = []
    def __repr__(self):
        out_str = "Routing Table\n"
        for entry in self.table:
            out_str += str(entry) + "\n"
        return out_str
    def __iter__(self):
        return iter(self.table)
    def add_entry(self, entry):
        self.table.append(entry)
    def find_entry(self, ip):
        """ Finds most specific routing table entry, breaking ties on metric """
        # Dummmy variable
        dummy_param_list = ["0.0.0.0", 0xFFFFFFFF, "0.0.0.0", "00:00:00:00:00:00", "eth0", "00:00:00:00:00:00"]
        bestEntry = RoutingTable.RoutingTableEntry(dummy_param_list,sys.maxint)

        for entry in self.table:
            # Check the subnet
            if ipstr_to_hex(entry.dest)&entry.netmask == ipstr_to_hex(ip)&entry.netmask:
                # Always take more specific match
                if entry.netmask < bestEntry.netmask:
                    bestEntry = entry
                # If equally specific, take entry with lower metric
                elif entry.netmask == bestEntry.netmask:
                     if entry.metric < bestEntry.metric:
                        bestEntry = entry
        return bestEntry

# Global Variables
# routing_table = RoutingTable()
# arp_table = []


class Router:
    def __init__(self, config_dict, my_ip):
        """
        Input: a dictionary of type specified in util.py, an IP addr as a string
        """
        self.config_dict = config_dict
        self.my_ip = my_ip
        self.routing_table = RoutingTable()
        self.arp_table = []


    def send_icmp(self, pkt, icmp_type, icmp_code):
        """
        input: bad packet, with type and code of desired ICMP message
        output: none
        """
        # Craft ICMP response
        icmp_pkt = Ether()/IP()/ICMP()

        # Switch src and dest
        icmp_pkt[IP].src = pkt[IP].dst
        icmp_pkt[IP].dst = pkt[IP].src
        
        # Set type and code
        icmp_pkt[ICMP].type = icmp_type
        icmp_pkt[ICMP].code = icmp_code

        # Get IP header and 8 bytes, allows ICMP dest to demux
        ip_hdr_len = pkt[IP].ihl
        data = str(pkt[IP])[0:ip_hdr_len*4 + 8]

        out_pkt = icmp_pkt/data

        # Get src and dest MAC, and out iface
        iface = ""
        entry_found = 0
        for entry in self.routing_table:
            if out_pkt[IP].dst == entry.dest:
                out_pkt.dst = entry.gateway_mac
                out_pkt.src = entry.local_mac
                iface = entry.interface
                entry_found = 1

        print "======= ICMP Packet ========"

        if not entry_found:
            print "Entry not found"
            for arp_entry in self.arp_table:
                print arp_entry
                if out_pkt[IP].dst in arp_entry:
                    print "Found arp entry!"
                    out_pkt.dst = arp_entry[1]
                    iface = arp_entry[2]
            print " - End ARP Table -"
            
            print "iface: " + str(iface)
            process = subprocess.Popen(["ifconfig", str(iface)], stdout=subprocess.PIPE)
            output = process.communicate()[0]
            print "output: " + str(output)
            output_list = output.replace('\n', ' ').split()

            # This is hardcoded based on the output of ifconfig on the nodes,
            # as the local mac address is the word after HWaddr
            out_pkt.src = output_list[output_list.index('HWaddr')+1]

        out_pkt.show()

        sendp(out_pkt, iface=iface, verbose=0)


    def pkt_callback(self, pkt):
        """
        input: a packet
        output: none
        side effects: handles this step of routing for input packet
        """

        #Determine if it is an IP packet. If not then return
        if IP not in pkt:
            return

        dest_ip = pkt[IP].dst

        # If the dest IP is local to this computer or LAN, kernel handles packet
        #if "10.99.0" in dest_ip or "10.10.0" in dest_ip or "192.168" in dest_ip:
        #    return
        # Change to starts with
        # TODO
        # -------------------
        # remove hard coding
        # -------------------

        # drop packet if dest IP is directly connected, or if dest IP is this node
        if any(dest_ip in ip for ip in self.config_dict["adjacent_to"][self.my_ip]) or "192.168" in dest_ip:
            return
        

        # Is the destination *network* in your routing table, if not, send ICMP "Destination host unreachable", then return
        has_route = False
        for entry in self.routing_table:
            # Make sure these comparisons are valid
            if ((ipstr_to_hex(dest_ip) & entry.netmask) == (ipstr_to_hex(entry.dest) & entry.netmask)):
                print dest_ip + " is reachable"
                has_route = True

        if not has_route:
            print dest_ip + " is unreachable"
            send_icmp(pkt, icmp_type=3, icmp_code=11)
            return

        # Decrement the TTL. If TTL=0, send ICMP for TTL expired and return.
        pkt[IP].ttl -= 1
        if pkt[IP].ttl < 1:
            send_icmp(pkt, icmp_type=11, icmp_code=0)
            return

        # Find the next hop (gateway) for the destination *network*
        routing_entry = self.routing_table.find_entry(dest_ip)
        gateway = routing_entry.gateway

        # Determine the outgoing interface and MAC address needed to reach the next-hop router
        out_iface = routing_entry.interface

        # Modify the SRC and DST MAC addresses to match the outgoing interface and the DST MAC found above
        # Drop packet if src is equal to local_mac, as this means pkt is duplicate
        if pkt.src == routing_entry.local_mac:
            return
        pkt.src = routing_entry.local_mac
        pkt.dst = routing_entry.gateway_mac

        # Update the IP header checksum
        del pkt[IP].chksum
        pkt = pkt.__class__(str(pkt))

        #Send the packet out the proper interface as required to reach the next hop router. Use:
        sendp(pkt, iface=out_iface, verbose=0)

    def setup(self):
        # TODO
        # -------------------
        # Make this extensible to a general case / load info from config file
        # i.e. remove hard coding
        # -------------------

        # Disable ICMP echos
        subprocess.Popen('sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1'.split())
        subprocess.Popen('sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1'.split())

        # Ping the routers and node0 w/ TTL 1 --> ARP created
        # subprocess.Popen('ping 10.99.0.1 -c 1'.split())
        # subprocess.Popen('ping 10.99.0.2 -c 1'.split())
        # subprocess.Popen('ping 10.10.0.1 -c 1'.split())
        # TODO
        # -----
        # ping each node in self.config_dict[self.my_ip]
        # -----
        for ip in self.config_dict["adjacent_to"][self.my_ip]:
            ping_str = 'ping ' + str(ip) + ' -c 1'
            subprocess.Popen(ping_str.split())

        # Construct Routing Table
        # subnet1 = ["10.1.0.0", 0xFFFFFF00, "10.99.0.1"]
        # subnet2 = ["10.1.2.0", 0xFFFFFF00, "10.99.0.2"]
        # subnet3 = ["10.1.3.0", 0xFFFFFF00, "10.99.0.2"]
        # Hardcoded IP mappings
        # TODO
        # -----
        # for each dest, make a subnet entry from dest to gateway IP
        # -----
        router_table = []
        for dest in self.config_dict["dests"]:
            gateway_ip = self.config_dict["next_hop"][self.my_ip][dest]
            entry = [str(dest), 0xFFFFFF00, gateway_ip]
            router_table.append(entry)
        

        # Look at ARP table for corresponding info
        process = subprocess.Popen("arp -a".split(), stdout=subprocess.PIPE)
        output = process.communicate()[0]

        # Split twice so we can get individual words per line
        output_list = output.split('\n')
        output_split_list = [a.split() for a in output_list]

        # Parse the output of arp -a into a table (a list of lists of 3 string fields)
        # The gateway IP should be the second word on the line, but is surrounded
        #   by parentheses
        arp_table = [[a[1].translate(None, '()'),a[3],a[6]] for a in output_split_list if len(a) > 6]
        print "arp table:\n\n" + str(arp_table)

        # Add the dest MAC info into the subnet info
        # for entry in arp_table:
        #     if entry[0] == subnet1[2]:
        #         subnet1 += entry[1:]
        #     if entry[0] == subnet2[2]:
        #         subnet2 += entry[1:]
        #     if entry[0] == subnet3[2]:
        #         subnet3 += entry[1:]
        # TODO
        # -----
        # for each dest, make a subnet entry from dest to gateway IP
        # -----
        for i in range(len(router_table)):
            for arp_entry in arp_table:
                if arp_entry[0] == router_table[i][2]:
                    router_table[i] += arp_entry[1:]
                    break

        # For each unique interface found above, we want to find the local mac
        #  that corresponds to it using ifconfig
        unique_interface = list(set([a[2] for a in arp_table]))
        interface_destmac_dict = {}
        for interface in unique_interface:
            process = subprocess.Popen(["ifconfig", str(interface)], stdout=subprocess.PIPE)
            output = process.communicate()[0]
            output_list = output.replace('\n', ' ').split()

            # This is hardcoded based on the output of ifconfig on the nodes,
            # as the local mac address is the word after HWaddr
            local_mac = output_list[output_list.index('HWaddr')+1]
            interface_destmac_dict[interface] = local_mac

        print "subnet3: ", subnet3
        print "interface dict: ", interface_destmac_dict

        # Combine the parameters we have gathered for each subnet and add them
        #  to the routing table
        # subnet1.append(interface_destmac_dict[subnet1[-1]])
        # subnet2.append(interface_destmac_dict[subnet2[-1]])
        # subnet3.append(interface_destmac_dict[subnet3[-1]])
        for i in range(len(router_table)):
            router_table[i].append(interface_destmac_dict[router_table[i][-1]])

        # subnet1Entry = RoutingTable.RoutingTableEntry(subnet1)
        # subnet2Entry = RoutingTable.RoutingTableEntry(subnet2)
        # subnet3Entry = RoutingTable.RoutingTableEntry(subnet3)
        # routing_table.add_entry(subnet1Entry)
        # routing_table.add_entry(subnet2Entry)
        # routing_table.add_entry(subnet3Entry)
        # TODO
        # -----
        # add entries from router_table to self.routing_table
        # -----
        

        routing_table = RoutingTable()
        for entry in router_table:
            routing_entry = RoutingTable.RoutingTableEntry(entry)
            routing_table.add_entry(routing_entry)

        self.routing_table = routing_table
        self.arp_table = arp_table



if __name__ == "__main__":
    # Parse command line input:
    # python traffic-simulator.py filename my_ip
    args = sys.argv
    config_filename = str(args[1])
    my_ip = str(args[2])

    # First, parse the config file
    config_dict = parse_config(config_filename)

    # Instantiate this router
    my_router = Router(config_dict, my_ip)

    #First setup your routing table and any other init code
    my_router.setup()
    print "routing_table: ", my_router.routing_table

    #Start the packet sniffer
    sniff(prn=my_router.pkt_callback, store=0)
