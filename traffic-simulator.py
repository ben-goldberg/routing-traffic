# Author: Ben Goldberg
from scapy.all import *
from trafficlight import TrafficLight
import util, sys, multiprocessing

def packet_sniff(mac_to_dir_dict, north_queue, east_queue, south_queue, west_queue):
    """
    input: a dict of source MAC -> received direction mappings, 
           and 4 multiprocessing queues: one for each receive direction
    output: None
    side effects: puts packet into appropriate multiprocessing queue
    details: this is the function for the packet sniffing process, it simply
             calls sniff() with the appropriate parameters
    """
    print mac_to_dir_dict
    #Start the packet sniffer
    sniff(prn = receive_packet(mac_to_dir_dict, north_queue, east_queue, \
                south_queue, west_queue), store=0)

def receive_packet(mac_to_dir_dict, north_queue, east_queue, south_queue, west_queue):
    """
    input: a packet, a dict of dest MAC -> received direction mappings, 
           and 4 multiprocessing queues: one for each receive direction
    output: None
    side effects: puts packet into appropriate multiprocessing queue
    details: this is the sniff() callback function for handling a received packet
    """
    def pkt_callback(pkt):
        dest_mac = pkt.dst
        if dest_mac in mac_to_dir_dict["adjacent_north"]:
            north_queue.put(pkt)
        elif dest_mac in mac_to_dir_dict["adjacent_east"]:
            east_queue.put(pkt)
        elif dest_mac in mac_to_dir_dict["adjacent_south"]:
            south_queue.put(pkt)
        elif dest_mac in mac_to_dir_dict["adjacent_west"]:
            west_queue.put(pkt)
    return pkt_callback

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
                    args=(mac_to_dir_dict, traffic_light.north_queue, \
                    traffic_light.east_queue, traffic_light.south_queue, \
                    traffic_light.west_queue))

    packet_listener.start()

    traffic_light.start()





    
