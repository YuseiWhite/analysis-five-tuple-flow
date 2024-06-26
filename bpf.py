#!/usr/bin/python3
# -*- coding: utf-8 -*-


from bcc import BPF
import json
import sys
import time
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct

from analyze import analyze_and_save

# example: `sudo python3 bpf.py wlp0s20f3 -S`
def main():
    def usage():
        print("Usage: {0} <ifdev> <flag>".format(sys.argv[0]))
        exit(1)

    bpf_program_file_path = "bpf.c"
    with open(bpf_program_file_path, 'r') as file:
        bpf_program = file.read()

    print("start processing")

    data_name = input("What application analysis do you want to see?: ")
    data_file_path = f"data/{data_name.lower()}.json"

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

        # you can change this num
        num_of_pixel = 2048

        while not break_while:
            try:
                dt = time.strftime("%H:%M:%S")

                for k, v in sessions.items():
                    if v.interarrival_time > 1:
                      five_tuple_flow_dict = {
                        "packet_size": v.packet_size,
                        "interarrival_time": v.interarrival_time,
                        "direction": v.direction,
                        "transport_protocol": k.protocol
                      }
                      five_tuple_flow_list.append(five_tuple_flow_dict)

                      if len(five_tuple_flow_list) >= (num_of_pixel * num_of_pixel):
                        break_while = True
                        break

                # time.sleep(1)
            except KeyboardInterrupt:
                break

        with open(data_file_path, 'w') as json_file:
            json.dump(five_tuple_flow_list, json_file, indent=4)
        print(f"saved data of five tuple flow to {data_file_path}!")

        analyze_and_save(data_name, num_of_pixel, five_tuple_flow_list)

        print("processed sucessfully!")

    finally:
        b.remove_xdp(device, flags)
        print("finished pbf program")


if __name__ == '__main__':
    main()
