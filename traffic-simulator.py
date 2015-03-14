# Author: Ben Goldberg
from scapy.all import *
from trafficlight import TrafficLight
import util, sys

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
    my_traffic_light = TrafficLight(config_dict, my_ip)

    print "routing_table: ", my_traffic_light.router.routing_table

    #Start the packet sniffer
    sniff(prn=my_traffic_light.handle_packet, store=0)
