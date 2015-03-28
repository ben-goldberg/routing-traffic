# Author: Ben Goldberg
from scapy.all import *
import router
import multiprocessing
import util
import Queue, sys

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
        self.phase_0_queue = Queue.Queue()
        self.phase_1_queue = Queue.Queue()
        self.phase_2_queue = Queue.Queue()
        self.phase_3_queue = Queue.Queue()
        self.router = router.Router(config_dict, my_ip)
        self.ip_to_dir_dict = util.match_IP_to_direction(config_dict, my_ip)

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
        return self.router.prep_pkt(pkt)

    def receive_traffic(self):
        """
        inputs: None
        outputs: None
        side effects: takes one packet out of each multiprocess queue,
                      prepares them to be sent, and places them in the
                      queue appropriate for their send state
        """
        pkt_list = []
        pkt_list.append( (util.safe_get(north_queue),"north") )
        pkt_list.append( (util.safe_get(east_queue), "east") )
        pkt_list.append( (util.safe_get(south_queue),"south") )
        pkt_list.append( (util.safe_get(west_queue), "west") )

        for pkt, src in pkt_list:
            if pkt is None:
                pass
            else:
                # Packets were string-ed to enable pickling, now packetify them
                pkt = Ether(pkt)

                # Check if packet should be dropped
                if self.router.should_drop_pkt(pkt):
                    return

                # Since packet is valid, prepare it to be sent
                pkt, iface = self.router.prep_pkt(pkt)

                # Place packet/iface into appropriate queue for send state
                self.queue_pkt_to_send(pkt, iface, src)


    def queue_pkt_to_send(self, pkt, iface, src_dir):
        """
        input: a pkt, an iface to send it over, and a string representing the
               direction the pkt came from
        output: None
        side effects: pkt/iface are placed into appropriate phase queue
        """
        dest_dir = self.get_dest_dir(pkt)

        if src_dir == "north":
            # If turning left
            if dest_dir == "east":
                self.phase_0_queue.put((pkt,iface))
            # Packet must be going straight, or turning right
            else:
                self.phase_1_queue.put((pkt,iface))

        else if src_dir == "east":
            # If turning left
            if dest_dir == "south":
                self.phase_2_queue.put((pkt,iface))
            # Packet must be going straight, or turning right
            else:
                self.phase_3_queue.put((pkt,iface))

        else if src_dir == "south":
            # If turning left
            if dest_dir == "west":
                self.phase_0_queue.put((pkt,iface))
            # Packet must be going straight, or turning right
            else:
                self.phase_1_queue.put((pkt,iface))

        else if src_dir == "west":
            # If turning left
            if dest_dir == "north":
                self.phase_2_queue.put((pkt,iface))
            # Packet must be going straight, or turning right
            else:
                self.phase_3_queue.put((pkt,iface))


    def get_dest_dir(self, pkt):
        """
        input: a pkt
        output: a string (either "north", "south", "east", "west") representing
                the direction the pkt must travel to reach its next-hop
        """
        routing_entry = self.router.routing_table.find_entry(pkt[IP].dst)
        try:
            return self.ip_to_dir_dict[routing_entry.gateway]
        except KeyError:
            print "Key error when matching gateway IP to direction"
            sys.exit()


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

            # Move packets from multiprocess-queues to state-based-queue
            self.receive_traffic()

            # Based on state, get a packet from each of the allowable directions
            # North and South are allowed to turn
            if self.light_state == 0:
                new_pkt, iface = util.safe_get(self.phase_0_queue)

            # North and South are allowed to go straight    
            elif self.light_state == 1:
                new_pkt, iface = util.safe_get(self.phase_1_queue)

            # East and West are allowed to turn
            elif self.light_state == 2:
                new_pkt, iface = util.safe_get(self.phase_2_queue)

            # East and West are allowed to go straight
            else:
                new_pkt, iface = util.safe_get(self.phase_3_queue)

            # Send the packet out the proper interface as required to reach the next hop router
            sendp(new_pkt, iface=iface, verbose=0)

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


