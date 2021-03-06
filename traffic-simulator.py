# Author: Ben Goldberg
from scapy.all import *
from trafficlight import TrafficLight
import util, sys, multiprocessing
import time

def packet_sniff(dir_to_mac_dict, north_queue, east_queue, south_queue, west_queue):
    """
    input: a dict of source MAC -> received direction mappings, 
           and 4 multiprocessing queues: one for each receive direction
    output: None
    side effects: puts packet into appropriate multiprocessing queue
    details: this is the function for the packet sniffing process, it simply
             calls sniff() with the appropriate parameters
    """
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

        current_time = str(time.time())
        dest_mac = pkt.dst

        # scapy packets cannot be pickled, so I must stringify them here and 
        # re-packetify them on the receiving end
        pkt_str = str(pkt)

        # Put time into pkt_str, so main process can determine time passage
        out_pkt = current_time + " "  + pkt_str
        
        if dir_to_mac_dict["adjacent_north"] == dest_mac:
            print "found pkt from north direction"
            north_queue.put(out_pkt)

        elif dir_to_mac_dict["adjacent_east"] == dest_mac:
            print "found pkt from east direction"
            east_queue.put(out_pkt)

        elif dir_to_mac_dict["adjacent_south"] == dest_mac:
            print "found pkt from south direction"
            south_queue.put(out_pkt)
            
        elif dir_to_mac_dict["adjacent_west"] == dest_mac:
            print "found pkt from west direction"
            west_queue.put(out_pkt)

    return pkt_callback


def main(args):
    """
    Expects command line input: python traffic-simulator.py config_file.txt my_ip
    """
    config_filename = str(args[1])
    my_ip = str(args[2])

    # First, parse the config file
    config_dict = util.parse_config(config_filename)

    # Instantiate this traffic light
    traffic_light = TrafficLight(config_dict, my_ip)

    dir_to_mac_dict = util.match_MAC_to_direction(traffic_light.router, config_dict)

    # Make seperate process to listen for packets
    packet_listener = multiprocessing.Process(target=packet_sniff, \
                    args=(dir_to_mac_dict, traffic_light.north_queue, \
                    traffic_light.east_queue, traffic_light.south_queue, \
                    traffic_light.west_queue))

    packet_listener.start()
    traffic_light.start()


if __name__ == "__main__":
    main(sys.argv)






    
