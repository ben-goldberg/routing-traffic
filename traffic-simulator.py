# Author: Ben Goldberg
from scapy.all import *
from trafficlight import TrafficLight
import util, sys

def packet_sniff(mac_to_dir_dict, north_array, east_array, south_array, west_array):
    """
    input: a dict of source MAC -> received direction mappings, 
           and 4 multiprocessing arrays: one for each receive direction
    output: None
    side effects: puts packet into appropriate multiprocessing queue
    details: this is the function for the packet sniffing process, it simply
             calls sniff() with the appropriate parameters
    """
    #Start the packet sniffer
    sniff(prn = receive_packet(mac_to_dir_dict, north_array, east_array, \
                south_array, west_array), store=0)

def receive_packet(pkt, mac_to_dir_dict, north_array, east_array, south_array, west_array):
    """
    input: a packet, a dict of source MAC -> received direction mappings, 
           and 4 multiprocessing arrays: one for each receive direction
    output: None
    side effects: puts packet into appropriate multiprocessing queue
    details: this is the sniff() callback function for handling a received packet
    """
    source_mac = pkt.src
    if pkt in mac_to_dir_dict["north"]:
        north_array.put(pkt)
    elif pkt in mac_to_dir_dict["east"]:
        east_array.put(pkt)
    elif pkt in mac_to_dir_dict["south"]:
        south_array.put(pkt)
    elif pkt in mac_to_dir_dict["west"]:
        west_array.put(pkt)

if __name__ == "__main__":
    """
    Expects command line input: python traffic-simulator.py filename my_ip
    """
    args = sys.argv
    config_filename = str(args[1])
    my_ip = str(args[2])

    # First, parse the config file
    config_dict = util.parse_config(config_filename)

    # Instantiate this traffic light
    traffic_light = TrafficLight(config_dict, my_ip)

    print "routing_table: ", traffic_light.router.routing_table

    mac_to_dir_dict = util.match_MAC_to_direction(traffic_light.router, config_dict)

    packet_listener = multiprocessing.Process(target=packet_sniff, \
                    args=(mac_to_dir_dict, traffic_light.north_array, \
                    traffic_light.east_array, traffic_light.south_array, \
                    traffic_light.west_array))

    packet_listener.start()

    traffic_light.start()





    
