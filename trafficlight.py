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
        outputs: None
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
                if self.router.should_drop_pkt(pkt):
                    return

                # Since packet is valid, prepare it to be sent
                pkt, iface = self.router.prep_pkt(pkt)

                # Place packet/iface into appropriate queue for send state
                self.queue_pkt_to_send(pkt, iface, src, time_arrived)


    def queue_pkt_to_send(self, pkt, iface, src_dir, time_arrived):
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
                self.phase_0_queue.put((pkt,iface, time_arrived))
            # Packet must be going straight, or turning right
            else:
                self.phase_1_queue.put((pkt,iface, time_arrived))

        elif src_dir == "east":
            # If turning left
            if dest_dir == "south":
                self.phase_2_queue.put((pkt,iface, time_arrived))
            # Packet must be going straight, or turning right
            else:
                self.phase_3_queue.put((pkt,iface, time_arrived))

        elif src_dir == "south":
            # If turning left
            if dest_dir == "west":
                self.phase_0_queue.put((pkt,iface, time_arrived))
            # Packet must be going straight, or turning right
            else:
                self.phase_1_queue.put((pkt,iface, time_arrived))

        elif src_dir == "west":
            # If turning left
            if dest_dir == "north":
                self.phase_2_queue.put((pkt,iface, time_arrived))
            # Packet must be going straight, or turning right
            else:
                self.phase_3_queue.put((pkt,iface, time_arrived))


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
                new_pkt, iface, time_arrived = next_obj

            # If state changed on this iteration, sleep for several seconds to
            # represent time it takes stopped cars to accelerate through
            if state_change:
                time.sleep(3)

            # Send the packet out the proper interface as required to reach the next hop router
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
        return self.fixed_timer()

    def expert_interarrival(self):
        """
        input: None
        output: traffic light state
        details: Dynamically chooses between three different fixed-time cycle
                 lengths depending on interarrival time (the amount of time
                 that passes between the arrival of two pkts).
                 Ranks each phase by shortest interarrival time, rotates 
                 through phases in order, sets time for next phase based on
                 its interarrival rank.
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

            # Get current interarrival time (time between 2 pkts arriving)
            arrival_time_dict = {}
            queue_list = [self.phase_0_queue, self.phase_1_queue, self.phase_2_queue, self.phase_3_queue]

            # For each queue, try to get arrival time of 2 most recent pkts
            for queue in queue_list:
                arrival_time_dict[queue] = []
                for i in -1,-2:
                    try:
                        _, _, time_arrived = queue.queue[i]
                        arrival_time_dict[queue].append(time_arrived)
                    except IndexError:
                        arrival_time_dict[queue].append(None)
                        break

            # Get interarrival time for each phase queue
            interarrival_dict = {}
            for queue in queue_list:
                # If 1 or 0 pkts were in that queue, interarrival time is inf
                if None in arrival_time_dict[queue]:
                    interarrival_dict[queue] = sys.maxint
                else:
                    interarrival_time = arrival_time_dict[queue][-1] - arrival_time_dict[queue][-2]
                    interarrival_dict[queue] = interarrival_time

            # Sort queues based on interarrival time
            sorted_queues = sorted(queue_list, key=interarrival_dict.get)

            # Change to the next phase
            if self.light_state == 3:
                new_state = 0
            else:
                new_state = self.light_state + 1

            # Get rank of new phase's queue by shortest interarrival time
            new_queue_rank = sorted_queues.index(queue_list[new_state])

            # Depending on rank, set phase time for new queue, where queue 
            # with smallest interarrival time gets longest phase, queue with 
            # shortest interarrival time gets shortest phase
            if new_queue_rank == 0:
                new_phase_time = 50
            elif new_queue_rank == len(sorted_queues)-1:
                new_phase_time = 30
            else:
                new_phase_time = 40

            # Update dictionary
            self.traffic_alg_dict["last_change"] = current_time
            self.traffic_alg_dict["current_state_time"] = new_phase_time

            return new_state

            


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



