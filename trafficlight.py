# Author: Ben Goldberg
from scapy.all import *
import router
import multiprocessing
import util

class TrafficLight:
    def __init__(self, config_dict, my_ip):
        """
        details: light state can be 0,1,2,3 where:
                 0 -> North and South are allowed to turn
                 1 -> North and South are allowed to go straight
                 2 -> East and West are allowed to turn
                 3 -> East and West are allowed to go straight
        """
        self.light_state = 0
        self.north_queue = multiprocessing.Queue()
        self.east_queue = multiprocessing.Queue()
        self.south_queue = multiprocessing.Queue()
        self.west_queue = multiprocessing.Queue()
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

        print pkt

        # Since packet is valid, prepare it to be sent
        new_pkt = self.router.prep_pkt(pkt)

        # Send the packet out the proper interface as required to reach the next hop router
        sendp(new_pkt, iface=out_iface, verbose=0)

    def start(self):
        """
        input: None
        output: None
        side effects: handles all runtime aspects of traffic light, including
                      determining current light state, getting packets to route
                      from correct multiprocessing queue, and sending packets
                      to their appropriate destinations
        """
        # TODO
        # ---------------
        # add go straight vs turn left distinctions
        # ---------------
        while True:
            # First, determine new state
            self.light_state = self.determine_state()

            # Based on state, get a packet from each of the allowable directions
            # North and South are allowed to turn
            if self.light_state == 0:
                pkt1 = util.safe_get(self.north_queue)
                pkt2 = util.safe_get(self.south_queue)

            # North and South are allowed to go straight    
            elif self.light_state == 1:
                pkt1 = util.safe_get(self.north_queue)
                pkt2 = util.safe_get(self.south_queue)

            # East and West are allowed to turn
            elif self.light_state == 2:
                pkt1 = util.safe_get(self.east_queue)
                pkt2 = util.safe_get(self.west_queue)
                temp = IP(pkt2).show()
                if "127.0.0.1" in temp[IP].src:
                    print "received west packet:"
                    temp.show()
               

            # East and West are allowed to go straight
            else:
                pkt1 = util.safe_get(self.east_queue)
                pkt2 = util.safe_get(self.west_queue)

            # both packets were made into strings so they could be pickled
            # they must now be re-packetified
            pkt1 = IP(pkt1)
            pkt2 = IP(pkt2)

            # Send each packet to its destination
            self.handle_packet(pkt1)
            self.handle_packet(pkt2)

    def determine_state(self):
        """
        input: None
        output: returns traffic light state as follows:
                    0 -> North and South are allowed to turn
                    1 -> North and South are allowed to go straight
                    2 -> East and West are allowed to turn
                    3 -> East and West are allowed to go straight
        """
        # only currently implemented traffic control alg is simple stop sign
        return self.stop_sign()

    def stop_sign(self):
        """
        input: None
        output: traffic light state
        details: simply rotates between 4 states in order
        """
        if self.light_state == 3:
            return 0

        else:
            return self.light_state + 1



