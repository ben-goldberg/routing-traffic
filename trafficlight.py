# Author: Ben Goldberg
from scapy.all import *
import router
import multiprocessing

class TrafficLight:
    def __init__(self, config_dict, my_ip):
        self.light_state = 0
        self.north_array = multiprocessing.Queue()
        self.east_array = multiprocessing.Queue()
        self.south_array = multiprocessing.Queue()
        self.west_array = multiprocessing.Queue()
        self.router = router.Router(config_dict, my_ip)

        # Setup router
        self.router.setup()

    def handle_packet(self, pkt):
        """
        input: a packet
        output: None
        side effects: takes in received packet, drops packet if necessary,
                      or sends to its next hop
        """

        # Check if packet should be dropped
        drop_pkt = self.router.should_drop_pkt(pkt)
        if drop_pkt:
            return

        # Since packet is valid, prepare it to be sent
        new_pkt = self.router.prep_pkt(pkt)

        # Send the packet out the proper interface as required to reach the next hop router
        sendp(new_pkt, iface=out_iface, verbose=0)

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













