# Author: Ben Goldberg
# Adapted from https://github.com/ben-goldberg/userspace-routing
#     Written by Ben Goldberg and Louis Brann
from scapy.all import *
import socket
import sys
import subprocess
from util import *

# TODO
# -------------
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
        """ 
        Finds most specific routing table entry, breaking ties on metric 
        """
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
        side effects: sends appropriate ICMP message
        """
        print "sending ICMP"

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

        if not entry_found:
            for arp_entry in self.arp_table:
                if out_pkt[IP].dst in arp_entry:
                    out_pkt.dst = arp_entry[1]
                    iface = arp_entry[2]
            
            process = subprocess.Popen(["ifconfig", str(iface)], stdout=subprocess.PIPE)
            output = process.communicate()[0]
            output_list = output.replace('\n', ' ').split()

            # This is hardcoded based on the output of ifconfig on the nodes,
            # as the local mac address is the word after HWaddr
            out_pkt.src = output_list[output_list.index('HWaddr')+1]

        out_pkt.show()

        sendp(out_pkt, iface=iface, verbose=0)


    def should_drop_pkt(self, pkt):
        """
        input: a packet
        output: returns a bool representing if packet should be dropped or not
                True if pkt should be dropped, False otherwise
        side effects: If pkt's dest is not in routing table, sends ICMP message
        """
        #Determine if it is an IP packet. If not then return
        if IP not in pkt:
            return True

        dest_ip = pkt[IP].dst

        # If the dest IP is local to this computer or LAN, kernel handles packet
        netmasked_dest_ip = dest_ip[:nindex(dest_ip, '.', 2)]
        if any(netmasked_dest_ip in ip for ip in self.config_dict["adjacent_to"][self.my_ip]):
            return True

        # Drop packet if loopback addr is present
        if "127.0.0.1" in dest_ip:
            return True

        # Drop packets from control network
        if "192.168" in dest_ip:
            return True

        print "useful pkt:"
        pkt.show()

        # If destination *network* not in routing table, send ICMP "Destination host unreachable", then return
        has_route = False
        for entry in self.routing_table:
            # Make sure these comparisons are valid
            if ((ipstr_to_hex(dest_ip) & entry.netmask) == (ipstr_to_hex(entry.dest) & entry.netmask)):
                print dest_ip + " is reachable"
                has_route = True

        if not has_route:
            print dest_ip + " is unreachable"
            #self.send_icmp(pkt, icmp_type=3, icmp_code=11)
            return True

        # If Packet's Time-To-Live is 1, this iteration will drop it to 0
        # Thus, packet should be dropped, send ICMP for TTL expired
        if pkt[IP].ttl == 1:
            print "ttl expired"
            #self.send_icmp(pkt, icmp_type=11, icmp_code=0)
            return True

        # Drop packet if src is equal to local_mac, as this means pkt is duplicate
        if pkt.src == self.routing_table.find_entry(pkt[IP].dst).local_mac:
            return True

        # If we get this far, the packet is valid and should not be dropped
        return False

    def prep_pkt(self, pkt):
        """
        input: a valid packet
        output: returns a packet to be sent, and the interface to send it over
        side effects: handles this step of routing for input packet
        details: this function assumes a valid packet, i.e. a packet which
                 should not be dropped at this router
        """
        # Decrement the TTL. 
        pkt[IP].ttl -= 1
        
        # Find the next hop (gateway) for the destination *network*
        routing_entry = self.routing_table.find_entry(pkt[IP].dst)
        gateway = routing_entry.gateway

        # Determine the outgoing interface and MAC address needed to reach the next-hop router
        out_iface = routing_entry.interface

        # Modify the SRC and DST MAC addresses to match the outgoing interface and the DST MAC found above
        pkt.src = routing_entry.local_mac
        pkt.dst = routing_entry.gateway_mac

        # Update the IP header checksum
        del pkt[IP].chksum
        pkt = pkt.__class__(str(pkt))

        return pkt, out_iface

    def setup(self):

        # Disable ICMP echos
        subprocess.Popen('sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1'.split())
        subprocess.Popen('sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1'.split())

        # Ping the routers and node0 w/ TTL 1 --> ARP created
        for ip in self.config_dict["adjacent_to"][self.my_ip]:
            ping_str = 'ping ' + str(ip) + ' -c 1'
            subprocess.Popen(ping_str.split())

        # Construct Routing Table
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

        # Combine the parameters we have gathered for each subnet and add them
        #  to the routing table
        for i in range(len(router_table)):
            router_table[i].append(interface_destmac_dict[router_table[i][-1]])

        routing_table = RoutingTable()
        for entry in router_table:
            routing_entry = RoutingTable.RoutingTableEntry(entry)
            routing_table.add_entry(routing_entry)

        self.routing_table = routing_table
        self.arp_table = arp_table
        