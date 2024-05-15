#!/usr/bin/python3
# -*- coding: utf-8 -*-


from bcc import BPF
import sys
import time
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct

from analyze import analyze_and_save

def main():
    def usage():
        print("Usage: {0} <ifdev> <flag>".format(sys.argv[0]))
        exit(1)

    bpf_program_file_path = "bpf.c"
    with open(bpf_program_file_path, 'r') as file:
        bpf_program = file.read()

    print("start processing")

    data_name = input("What application analysis do you want to see?: ")
    # you should change all cha to lowercase
    print(data_name)
    # make a json file naming `data_name` to store data from IP packets

    # example: `sudo python3 bpf.py wlp0s20f3 -S`
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        usage()
    device = sys.argv[1]
    flags = 0
    offload_device = None
    if len(sys.argv) == 3:
        if "-S" in sys.argv:
            # XDP_FLAGS_SKB_MODE
            flags |= BPF.XDP_FLAGS_SKB_MODE
        if "-D" in sys.argv:
            # XDP_FLAGS_DRV_MODE
            flags |= BPF.XDP_FLAGS_DRV_MODE
        if "-H" in sys.argv:
            # XDP_FLAGS_HW_MODE
            offload_device = device
            flags |= BPF.XDP_FLAGS_HW_MODE
    b = BPF(text=bpf_program)


    try:
        fn = b.load_func("record_packet", BPF.XDP)
        b.attach_xdp(device, fn=fn, flags=flags)

        sessions = b.get_table("sessions")
        
        five_tuple_flow_list = []

        break_while = False

        while not break_while:
            try:
                dt = time.strftime("%H:%M:%S")

                for k, v in sessions.items():
                    if v.interarrival_time > 1:
                      # packet size
                      # print("packet_size:", v.packet_size) # $ sudo tcpdump -i wlp0s20f3 -vvv

                      # # interarrival time
                      # print("interarrival time: ", v.interarrival_time)

                      # # direction
                      # print("direction:", v.direction)
                      
                      # # protocol
                      # print("transport protocol:", k.protocol)

                      five_tuple_flow_dict = {
                        "packet_size": v.packet_size,
                        "interarrival_time": v.interarrival_time,
                        "direction": v.direction,
                        "transport_protocol": k.protocol
                      }
                      print(five_tuple_flow_dict)
                      five_tuple_flow_list.append(five_tuple_flow_dict)

                      num_of_pixel = 256
                      if len(five_tuple_flow_list) >= (num_of_pixel * num_of_pixel):
                        break_while = True
                        break

                # time.sleep(1)
            except KeyboardInterrupt:
                break

        # print(five_tuple_flow_list)
        # print()
        # print(len(five_tuple_flow_list))

        analyze_and_save(data_name, num_of_pixel, five_tuple_flow_list)

        print("processed sucessfully!")

    finally:
        b.remove_xdp(device, flags)
        print("finished pbf program")


if __name__ == '__main__':
    main()
