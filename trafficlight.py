# Author: Ben Goldberg
from scapy.all import *
import router
import multiprocessing
import util, time
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
        self.avg_wait_time = util.LongRunAverage()
        self.traffic_alg_dict = self.setup_alg_dict()

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
        output: None
        side effects: takes one packet out of each multiprocess queue,
                      prepares them to be sent, and places them in the
                      queue appropriate for their send state
        """
        pkt_list = []
        pkt_list.append( (util.safe_get(self.north_queue),"north") )
        pkt_list.append( (util.safe_get(self.east_queue), "east") )
        pkt_list.append( (util.safe_get(self.south_queue),"south") )
        pkt_list.append( (util.safe_get(self.west_queue), "west") )

        for pkt, src in pkt_list:
            if pkt is None:
                pass
            else:
                # Pull attached timestamp out of pkt
                space_index = pkt.index(" ")
                time_arrived = pkt[:space_index]
                pkt = pkt[space_index+1:]

                # Packets were string-ed to enable pickling, now packetify them
                pkt = Ether(pkt)

                # Check if packet should be dropped
                locally_bound = False
                if self.router.should_drop_pkt(pkt):
                    # Don't immediately drop locally bound pkts
                    if self.router.pkt_locally_bound(pkt):
                        locally_bound = True
                    else:
                        return

                # Since packet is valid, prepare it to be sent
                pkt, iface = self.router.prep_pkt(pkt)

                # Place packet/iface into appropriate queue for send state
                self.queue_pkt_to_send(pkt, iface, src, time_arrived, locally_bound)


    def queue_pkt_to_send(self, pkt, iface, src_dir, time_arrived, locally_bound):
        """
        input: a pkt, an iface to send it over, and a string representing the
               direction the pkt came from
        output: None
        side effects: pkt/iface are placed into appropriate phase queue
        """
        # Get destination direction
        dest_dir = self.get_dest_dir(pkt)

        if src_dir == "north":
            # If turning left
            if dest_dir == "east":
                self.phase_0_queue.put((pkt, iface, time_arrived, locally_bound))
            # Packet must be going straight, or turning right
            else:
                self.phase_1_queue.put((pkt, iface, time_arrived, locally_bound))

        elif src_dir == "east":
            # If turning left
            if dest_dir == "south":
                self.phase_2_queue.put((pkt, iface, time_arrived, locally_bound))
            # Packet must be going straight, or turning right
            else:
                self.phase_3_queue.put((pkt, iface, time_arrived, locally_bound))

        elif src_dir == "south":
            # If turning left
            if dest_dir == "west":
                self.phase_0_queue.put((pkt, iface, time_arrived, locally_bound))
            # Packet must be going straight, or turning right
            else:
                self.phase_1_queue.put((pkt, iface, time_arrived, locally_bound))

        elif src_dir == "west":
            # If turning left
            if dest_dir == "north":
                self.phase_2_queue.put((pkt, iface, time_arrived, locally_bound))
            # Packet must be going straight, or turning right
            else:
                self.phase_3_queue.put((pkt, iface, time_arrived, locally_bound))


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
            try:
                return self.ip_to_dir_dict[pkt[IP].dst]

            except KeyError:
                print "Key error when matching gateway IP to direction"
                print "Exiting..."
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
        while True:

            # First, determine new state. Record if state has changed.
            state_change = False
            old_state = self.light_state
            self.light_state = self.determine_state()
            if self.light_state != old_state:
                state_change = True

            # Move packets from multiprocess-queues to state-based-queue
            self.receive_traffic()

            # Based on state, get a packet from each of the allowable directions
            # North and South are allowed to turn
            if self.light_state == 0:
                next_obj = util.safe_get(self.phase_0_queue)

            # North and South are allowed to go straight    
            elif self.light_state == 1:
                next_obj = util.safe_get(self.phase_1_queue)

            # East and West are allowed to turn
            elif self.light_state == 2:
                next_obj = util.safe_get(self.phase_2_queue)

            # East and West are allowed to go straight
            else:
                next_obj = util.safe_get(self.phase_3_queue)

            # Unpack object if it exists. Else, skip to the next loop iterarion
            if next_obj is None:
                continue
            else:
                new_pkt, iface, time_arrived, locally_bound = next_obj

            # If state changed on this iteration, sleep for several seconds to
            # represent time it takes stopped cars to accelerate through
            if state_change:
                time.sleep(3)

            # Send the packet out the proper interface as required to reach the next hop router
            # If packet is locally bound, kernel has already routed it to final dest
            if not locally_bound:
                sendp(new_pkt, iface=iface, verbose=0)

            # Find time pkt waited here, add this to avg wait time
            current_time = time.time()
            elapsed_time = current_time - float(time_arrived)
            self.avg_wait_time.add(elapsed_time)
            print "wait time: ", self.avg_wait_time.average

    def determine_state(self):
        """
        input: None
        output: returns traffic light state as follows:
                    0 -> North and South are allowed to turn
                    1 -> North and South are allowed to go straight
                    2 -> East and West are allowed to turn
                    3 -> East and West are allowed to go straight
        """
        return self.expert_interarrival()

    def expert_interarrival(self):
        """
        input: None
        output: traffic light state
        details: Dynamically chooses between three different fixed-time cycle
                 lengths depending on interarrival time (the amount of time
                 that passes between the arrival of two pkts).
                 Rrotates through phases in order, sets time for next phase
                 based on its interarrival time.
                 Loosely adapted from research by W. Wen. Paper available at
                 http://www.sciencedirect.com/science/article/pii/S0957417407001303

        """
        # Get number of seconds for current state
        fixed_state_time = self.traffic_alg_dict["current_state_time"]

        # Determine how much time has elapsed since last state change
        current_time = time.time()
        time_of_last_change = self.traffic_alg_dict["last_change"]
        elapsed_time = current_time - time_of_last_change

        # If it has been long enough
        if elapsed_time > fixed_state_time:
            print "Changing state!"

            # Get current queue
            arrival_time_dict = {}
            queue_list = [self.phase_0_queue, self.phase_1_queue, self.phase_2_queue, self.phase_3_queue]
            current_queue = queue_list[self.light_state]

            # Try to get arrival time of 2 most recent pkts
            arrival_time_list = []
            for i in -1,-2:
                try:
                    _, _, time_arrived, _ = current_queue.queue[i]
                    arrival_time_list.append(time_arrived)
                # If we don't find two packets, interarrival time = inf
                except IndexError:
                    arrival_time_list.append(sys.maxint)
                    break

            # Make each element a float
            for i in range(len(arrival_time_list)):
                arrival_time_list[i] = float(arrival_time_list[i])

            # Get interarrival time
            if len(arrival_time_list) == 2:
                interarrival_time = arrival_time_list[1] - arrival_time_list[0]
            else:
                interarrival_time = sys.maxint

            # Change to the next phase
            if self.light_state == 3:
                new_state = 0
            else:
                new_state = self.light_state + 1

            # Set phase time for new queue
            if interarrival_time < 1.7: # High traffic
                new_phase_time = 40
            elif interarrival_time < 3.4: # Medium traffic
                new_phase_time = 30
            else: # Low traffic
                new_phase_time = 10

            # Update dictionary
            self.traffic_alg_dict["last_change"] = current_time
            self.traffic_alg_dict["current_state_time"] = new_phase_time

            return new_state

        # If it hasn't been long enough, return current state
        else:
            return self.light_state

            


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

    def fixed_timer(self):
        """
        input: None
        output: traffic light state
        details: each state gets a fixed time, regardless of traffic conditions
                 expects that self.state["last_change"] is already instantiated
        """
        # Define number of seconds at each given state
        fixed_state_time = 40

        # Determine how much time has elapsed since last state change
        current_time = time.time()
        time_of_last_change = self.traffic_alg_dict["last_change"]
        elapsed_time = current_time - time_of_last_change

        # If it has been long enough
        if elapsed_time > fixed_state_time:
            print "Changing state!"

            # Update dictionary
            self.traffic_alg_dict["last_change"] = current_time

            # Change state
            if self.light_state == 3:
                return 0
            else:
                return self.light_state + 1

        # If it hasn't been long enough, return current state
        else:
            return self.light_state


    def setup_alg_dict(self):
        """
        input: None
        output: a dictionary
        details: creates and sets up a catchall dictionary for various traffic 
                 algs to use to save additional state
        """
        traffic_alg_dict = {}

        # Setup for fixed_timer
        traffic_alg_dict["last_change"] = time.time()

        # Setup for expert_interarrival
        traffic_alg_dict["current_state_time"] = 40

        return traffic_alg_dict



