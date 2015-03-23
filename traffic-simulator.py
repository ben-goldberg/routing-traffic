# Author: Ben Goldberg
from scapy.all import *
from trafficlight import TrafficLight
import util, sys, multiprocessing

def packet_sniff(dir_to_mac_dict, north_queue, east_queue, south_queue, west_queue):
    """
    input: a dict of source MAC -> received direction mappings, 
           and 4 multiprocessing queues: one for each receive direction
    output: None
    side effects: puts packet into appropriate multiprocessing queue
    details: this is the function for the packet sniffing process, it simply
             calls sniff() with the appropriate parameters
    """
    print dir_to_mac_dict
    #Start the packet sniffer
    sniff(prn = receive_packet(dir_to_mac_dict, north_queue, east_queue, \
                south_queue, west_queue), store=0)

def receive_packet(dir_to_mac_dict, north_queue, east_queue, south_queue, west_queue):
    """
    input: a packet, a dict of dest MAC -> received direction mappings, 
           and 4 multiprocessing queues: one for each receive direction
    output: None
    side effects: puts packet into appropriate multiprocessing queue
    details: this is the sniff() callback function for handling a received packet
    """
    def pkt_callback(pkt):

        dest_mac = pkt.dst

        # scapy packets cannot be pickled, so I must stringify them here and 
        # re-packetify them on the receiving end
        pkt_str = str(pkt)
        
        if dir_to_mac_dict["adjacent_north"] == dest_mac:
            print "found pkt from north direction"
            north_queue.put(pkt_str)

        elif dir_to_mac_dict["adjacent_east"] == dest_mac:
            print "found pkt from east direction"
            east_queue.put(pkt_str)

        elif dir_to_mac_dict["adjacent_south"] == dest_mac:
            print "found pkt from south direction"
            south_queue.put(pkt_str)
            
        elif dir_to_mac_dict["adjacent_west"] == dest_mac:
            print "found pkt from west direction"
            west_queue.put(pkt_str)

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

    dir_to_mac_dict = util.match_MAC_to_direction(traffic_light.router, config_dict)

    packet_listener = multiprocessing.Process(target=packet_sniff, \
                    args=(dir_to_mac_dict, traffic_light.north_queue, \
                    traffic_light.east_queue, traffic_light.south_queue, \
                    traffic_light.west_queue))

    packet_listener.start()

    traffic_light.start()





    
