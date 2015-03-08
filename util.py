# util.py
# author: Ben Goldberg
# Provides a list of utility functions for traffic simulation

import json

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


        