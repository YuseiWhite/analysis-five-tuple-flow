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
#define LOCAL_MAC_IP 0x0A2A00B2

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
  u64 interarrival_time;
  u32 direction;
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
    if (eth->h_proto != htons(ETH_P_IP)) {
      return XDP_PASS;
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
    if (iph->saddr != htonl(LOCAL_MAC_IP)) {
      return XDP_PASS;
    }

    // bpf_trace_printk("Source IP: %x\\n", iph->saddr);

    if (iph->saddr == htonl(LOCAL_MAC_IP)) {
        pkt_val.direction = 1; // 受信
    } else {
        pkt_val.direction = 0; // 送信
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
      zero.num_packets = 1; // for the initial packet to calc interarrival time
      zero.last_packet_timestamp = ts;
      zero.packet_size = 0;
      zero.tot_len_bytes = 0;
      zero.interarrival_time = 0;
      // zero.direction = (iph->saddr == htonl(LOCAL_MAC_IP)) ? 0 : 1;
      zero.direction = pkt_val.direction;
      sessions.update(&pkt_key, &zero);
      pkt_leaf = sessions.lookup(&pkt_key);
    } 
    if (pkt_leaf != NULL) {
      pkt_leaf->num_packets += 1;
      int64_t sport = pkt_leaf->sport;
      int64_t dport = pkt_leaf->dport;
      int64_t protocol = iph->protocol;
      int64_t tot_len = ntohs(iph->tot_len);

      int64_t time_diff = ts - pkt_leaf->last_packet_timestamp;
      if (time_diff < 0) {
        if (-time_diff > 10) {
          bpf_trace_printk("Significant timestamp reversal detected: current ts %lu, last ts %lu\\n", ts, pkt_leaf->last_packet_timestamp);
          return XDP_DROP;
        }
      } else {
        pkt_leaf->interarrival_time = time_diff;
      }
      pkt_leaf->last_packet_timestamp = ts;

      pkt_leaf->tot_len_bytes = ntohs(iph->tot_len);
      pkt_leaf->packet_size = pkt_val.packet_size;
      pkt_leaf->ip_header_length = pkt_val.ip_header_length;
      pkt_leaf->transport_header_length = pkt_val.transport_header_length;

      pkt_leaf->direction = pkt_val.direction;

      // pkt_leaf->direction = pkt_key.sport == sport;
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
    print("start processing")

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
    b = BPF(text=bpf_text)

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
                      five_tuple_flow_list.append(five_tuple_flow_dict)

                      # production env is 256?
                      if len(five_tuple_flow_list) >= 256:
                        break_while = True
                        break

                time.sleep(1)
            except KeyboardInterrupt:
                break

        print(five_tuple_flow_list)
        print()
        print(len(five_tuple_flow_list))

        import sys
        sys.path.append('/home/ubuntu/.pyenv/versions/3.10.14/lib/python3.10/site-packages')
        from PIL import Image
        import numpy as np


        # データの取得と処理
        packet_sizes = np.array([d['packet_size'] for d in five_tuple_flow_list])
        interarrival_times = np.array([d['interarrival_time'] for d in five_tuple_flow_list])
        protocols = np.array([d['transport_protocol'] for d in five_tuple_flow_list])

        # データの正規化
        normalized_sizes = (packet_sizes - packet_sizes.min()) / (packet_sizes.max() - packet_sizes.min())
        normalized_times = (interarrival_times - interarrival_times.min()) / (interarrival_times.max() - interarrival_times.min())

        # 画像のサイズを決定
        img_size = int(np.ceil(np.sqrt(len(five_tuple_flow_list))))

        # 画像データの初期化
        image = Image.new('RGB', (img_size, img_size))

        index = 0
        for i in range(img_size):
            for j in range(img_size):
                if index < len(five_tuple_flow_list):
                    # 色の設定: 赤色をTCP, 青色をUDPとする
                    color = (255, 0, 0) if protocols[index] == 6 else (0, 0, 255)
                    # 明るさの調整: パケットサイズとインターアライバルタイムの平均値を用いる
                    brightness = int((normalized_sizes[index] + normalized_times[index]) / 2 * 255)
                    color = tuple(min(max(c, 0), 255) for c in color)  # RGB値が255を超えないように調整
                    image.putpixel((i, j), color)
                index += 1

        # 画像の表示
        image.show()

        print("processed sucessfully!")

    finally:
        b.remove_xdp(device, flags)
        print("finished pbf program")
