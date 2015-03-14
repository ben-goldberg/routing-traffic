class TrafficLight:
    def __init__(self, config_dict, my_ip):
        self.light_state = 0
        self.north_array = []
        self.east_array = []
        self.south_array = []
        self.west_array = []
        self.router = Router(config_dict, my_ip)

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