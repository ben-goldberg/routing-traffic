# util.py
# author: Ben Goldberg
# Provides a list of utility functions for traffic simulation

import json

def match_MAC_to_direction(router, config_dict):
    """
    input: a router object, and a dictionary of type specified in parse_config
    output: returns a dictionary of dest MAC -> receive direction string
    example: {
                "12:34:56:78:9a:bc": "adjacent_north",
                "22:33:44:55:66:77": "adjacent_east",
                "55:44:33:66:55:76": "adjacent_south",
                "98:76:65:32:23:16": "adjacent_west"
             }
    """
    mac_to_dir_dict = {}
    my_ip = router.my_ip
    direction_list = ["adjacent_north", "adjacent_east", "adjacent_south", "adjacent_west"]
    for direction in direction_list:
        for entry in router.routing_table.table:
            if entry.gateway == config_dict[direction][my_ip]:
                dir_to_mac_dict[direction] = entry.local_mac
                break
    return mac_to_dir_dict

def ipstr_to_hex(ip_str):
    """
    input: an ip address as a scapy_table_string
    output: the same ip as an int
    """
    str_byte_list = ip_str.split('.')
    byte_list = [int(a) for a in str_byte_list]
    ip_hex = 0
    for i in range(len(byte_list)):
        ip_hex += byte_list[i] << (8 * (len(byte_list) - i - 1))
    return ip_hex

def hex_to_ipstr(hex_val):
    """
    input: an ip address as an int
    output: the same ip as a period-seperated string
    """
    o1 = str((hex_val / 16777216) % 256)
    o2 = str((hex_val / 65536) % 256)
    o3 = str((hex_val / 256) % 256)
    o4 = str((hex_val) % 256)
    return o1 + '.' + o2 + '.' + o3 + '.' + o4

def nindex(mystr, substr, n=0, index=0):
    for _ in xrange(n+1):
        index = mystr.index(substr, index) + 1
    return index - 1


def parse_config(in_file):
    """
    Input: path to config file
    Output: routing info as a dictionary type
    Details: config file contains a list of all dest IPs, and for each node 
             (including dests and routers) contains a list of all neighboring
             node IPs, for each node contains a dict of dest -> nexthop 
             mappings, all in below specified JSON format
    Example:{
                "dests": ["5.6.7.8", "9.10.11.12"],
                "routers": ["1.2.3.4"],
                "adjacent_to": {
                    "1.2.3.4": ["5.6.7.8", "9.10.11.12"],
                    "5.6.7.8": ["1.2.3.4"],
                    "9.10.11.12": ["1.2.3.4"]
                },
                "adjacent_north": {
                    "1.2.3.4": "5.6.7.8"
                },
                "adjacent_east": {},
                "adjacent_south": {
                    "1.2.3.4": "9.10.11.12"
                },
                "adjacent_west": {},
                "next_hop": {
                    "1.2.3.4": {
                        "5.6.7.8": "5.6.7.8",
                        "9.10.11.12": "9.10.11.12"
                    },
                    "5.6.7.8": {
                        "1.2.3.4": "1.2.3.4",
                        "9.10.11.12": "1.2.3.4"
                    },
                    "9.10.11.12": {
                        "1.2.3.4": "1.2.3.4",
                        "5.6.7.8": "1.2.3.4"
                    }
                }
            }
    """
    # read config file into a list
    with open(in_file) as config_file:
        config_dict = json.load(config_file)
        return config_dict


        