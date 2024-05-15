#include <uapi/linux/bpf.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#define DEBUG_BUILD
#define NUM_PACKETS 100
#define LOCAL_MAC_IP 0x0A2A00B2 // IP Address of My Macbook

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

    if (iph->saddr == htonl(LOCAL_MAC_IP)) {
        pkt_val.direction = 1; // reception
    } else {
        pkt_val.direction = 0; // transmission
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
    // goto record; // ignored tcp right now
    goto EOP;
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

      sessions.update(&pkt_key, pkt_leaf);

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
