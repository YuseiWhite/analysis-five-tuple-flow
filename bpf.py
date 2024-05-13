#!/usr/bin/python3
# -*- coding: utf-8 -*-


from bcc import BPF
import sys
import time
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct

def usage():
    print("Usage: {0} <ifdev> <flag>".format(sys.argv[0]))
    exit(1)

bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#define DEBUG_BUILD
#define NUM_PACKETS 100

struct pkt_key_t {
  u32 protocol;
  u32 saddr;
  u32 daddr;
  u32 sport;
  u32 dport;
};

struct pkt_leaf_t {
  u32 num_packets;
  u64 last_packet_timestamp;
  u32 saddr;
  u32 daddr;
  u32 sport;
  u32 dport;
  u32 packet_size;
  u32 tot_len_bytes;
  u32 ip_header_length;
  u32 transport_header_length;
};

BPF_TABLE("lru_hash", struct pkt_key_t, struct pkt_leaf_t, sessions, 1024);

int record_packet(struct xdp_md *ctx) {
  int64_t ts = bpf_ktime_get_ns();
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  struct ethhdr *eth = data;
  u64 nh_off = sizeof(*eth);
  struct iphdr *iph;
  struct tcphdr *th;
  struct udphdr *uh;
  struct pkt_key_t pkt_key = {};
  struct pkt_leaf_t pkt_val = {};
  int ip_header_length = 0;
  int transport_header_length = 0;

  pkt_key.protocol = 0;
  pkt_key.saddr = 0;
  pkt_key.daddr = 0;
  pkt_key.sport = 0;
  pkt_key.dport = 0;

  ethernet: {
    if (data + nh_off > data_end) {
      return XDP_DROP;
    }
    switch(eth->h_proto) {
      case htons(ETH_P_IP): goto ip;
      default: goto EOP;
    }
  }
  ip: {
    iph = data + nh_off;
    if ((void*)&iph[1] > data_end) {
      return XDP_DROP;
    }
    pkt_key.saddr    = iph->saddr;
    pkt_key.daddr    = iph->daddr;
    pkt_key.protocol = iph->protocol;

    pkt_val.ip_header_length = iph->ihl * 4;

    switch(iph->protocol) {
      case IPPROTO_TCP: goto tcp;
      case IPPROTO_UDP: goto udp;
      default: goto EOP;
    }
  }
  tcp: {
    th = (struct tcphdr *)(data + sizeof(struct ethhdr) + ip_header_length);
    if ((void *)(th + 1) > data_end) {
        return XDP_DROP;
    }
    
    pkt_val.transport_header_length = sizeof(struct tcphdr);
    if ((void*)((char*)th + pkt_val.transport_header_length) > data_end) {
        return XDP_DROP;
    }

    pkt_key.sport = ntohs(th->source);
    pkt_key.dport = ntohs(th->dest);

    pkt_val.packet_size = ntohs(iph->tot_len) - pkt_val.ip_header_length - pkt_val.transport_header_length;
    goto record;
  }
  udp: {
    uh = (struct udphdr *)((char*)iph + ip_header_length);
    if ((void*)(uh + 1) > data_end) {
        return XDP_DROP;
    }
    pkt_val.transport_header_length = sizeof(struct udphdr);

    pkt_key.sport = ntohs(uh->source);
    pkt_key.dport = ntohs(uh->dest);


    pkt_val.packet_size = ntohs(iph->tot_len) - pkt_val.ip_header_length - pkt_val.transport_header_length;
    goto record;
  }
  record: {
    struct pkt_leaf_t *pkt_leaf = sessions.lookup(&pkt_key);
    if (!pkt_leaf) {
      struct pkt_leaf_t zero = {};
      zero.sport = pkt_key.sport;
      zero.dport = pkt_key.dport;
      zero.saddr = pkt_key.saddr;
      zero.daddr = pkt_key.daddr;
      zero.num_packets = 0;
      zero.last_packet_timestamp = ts;
      zero.packet_size = 0;
      zero.tot_len_bytes = 0;
      sessions.update(&pkt_key, &zero);
      pkt_leaf = sessions.lookup(&pkt_key);
    }
    if (pkt_leaf != NULL) {
      pkt_leaf->num_packets += 1;
      int64_t sport = pkt_leaf->sport;
      int64_t dport = pkt_leaf->dport;
      int64_t protocol = iph->protocol;
      int64_t tot_len = ntohs(iph->tot_len);
      int64_t interval_time = 0;
      if (pkt_leaf->last_packet_timestamp > 0) {
        interval_time = ts - pkt_leaf->last_packet_timestamp;
      }
      pkt_leaf->last_packet_timestamp = ts;

      pkt_leaf->tot_len_bytes = ntohs(iph->tot_len);
      pkt_leaf->packet_size = pkt_val.packet_size;

      pkt_leaf->ip_header_length = pkt_val.ip_header_length;
      pkt_leaf->transport_header_length = pkt_val.transport_header_length;

      int64_t direction = pkt_key.sport == sport;
      sessions.update(&pkt_key, pkt_leaf);

      // ADD RAW PACKET COLLECTION PROGRAM

      return XDP_PASS;
    } else {
      return XDP_DROP;
    }
  }
  EOP: {
    return XDP_PASS;
  }
  return XDP_PASS;
}
"""

if __name__ == '__main__':

    # example: `sudo python3 test.py wlp0s20f3 -S`
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
    b = BPF(text=bpf_text)

    try:
        fn = b.load_func("record_packet", BPF.XDP)
        b.attach_xdp(device, fn=fn, flags=flags)

        sessions = b.get_table("sessions")
        # print("sessions", sessions)


        prev = 0
        while True:
            try:
                dt = time.strftime("%H:%M:%S")

                """
                - k
                struct pkt_key_t {
                    u32 protocol;
                    u32 saddr;
                    u32 daddr;
                    u32 sport;
                    u32 dport;
                };last_packet_timestamp

                - v
                struct pkt_leaf_t {
                    u32 num_packets;
                    u64 last_packet_timestamp;
                    u32 saddr;
                    u32 daddr;
                    u32 sport;
                    u32 dport;
                    u32 packet_size;
                };
                """

                for k, v in sessions.items():
                    print("bytes of ip header length:", v.ip_header_length)
                    print("bytes of transport header length:", v.transport_header_length)
                    print("bytes of tot_len:", v.tot_len_bytes)
                    print("packet_size:", v.packet_size) # already removed header, $ sudo tcpdump -i wlp0s20f3 -vvv
                    print()

                    prev = v.last_packet_timestamp

                    # print(dt, k.saddr, k.sport, k.daddr, k.dport, k.protocol, v.last_packet_timestamp, v.num_packets, v.packet_size)
                    # print(dt, k.protocol)

                    # if prev != 0:
                    #     print("interarrval_time", v.last_packet_timestamp - prev)
                time.sleep(1)
            except KeyboardInterrupt:
                break

    finally:
        b.remove_xdp(device, flags)
