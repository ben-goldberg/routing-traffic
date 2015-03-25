# Author: Ben Goldberg
import sys, socket, select
import random, time
import util

def generate_packet(config_dict):
    """
    input: a python dicitonary as specified in util.py
    output: a string to send, and the IP of a random node desination to send
            it to
    """
    msg = str(time.time())
    dest_ip = random.choice(config_dict["dests"])
    return msg, dest_ip

def main(argv):
    """
    Expects command line input: 
        python generate-traffic.py config_file.txt pkts_per_min
    """
    # Parse command line args
    config_file = argv[1]
    pkts_per_min = int(argv[2])

    # Time to wait between sending packets to satisfy pkts_per_min arg
    time_to_wait = (1.0/pkts_per_min) * 60.0

    # Parse the config file into dictionary
    config_dict = util.parse_config(config_file)

    # Make UDP socket
    udpPort = 44000
    try:
        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error, msg:
        print "Failed to create socket with error: " + msg
        sys.exit()

    # Now bind UDP socket to given port
    try:
        udpSocket.bind(("", udpPort))
    except socket.error, msg:
        print "Bind failed with error: " + msg
        sys.exit()

    udpSocket.setblocking(0)

    while True:
        # Generate one packet to a random other node
        msg, dest_ip = generate_packet(config_dict)

        # Send msg to desired destination
        udpSocket.sendto(msg, (dest_ip,udpPort))

        # Receive packets
        ready_to_read, _ , _ = select.select([udpSocket],[],[], .5)
        for recv_socket in ready_to_read[0]:
            recv_msg, recv_ip = recv_socket.recvfrom(1024)

        print recv_msg

    udpSocket.close()

if __name__ == "__main__":
    main(sys.argv)

