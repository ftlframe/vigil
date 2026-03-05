#include "vigil/capture.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "vigil/hashmap.h"
#include "vigil/parse.h"
#include "vigil/spscbuff.h"

/* CaptureHandle — opaque to consumers, defined only here */
struct CaptureHandle {
  Arena *arena;
  FlowTable *flow_table;
  pcap_t *pcap;
  RingBuf *buffer;
  int verbose;
};

#define ARENA_SIZE (1024 * 256) /* 256KB */
#define TABLE_CAPACITY 1024

/* EtherType constants */
#define PKT_IPv4 0x0800
#define PKT_ARP 0x0806
#define PKT_IPv6 0x86DD

void capture_foreach_flow(CaptureHandle *handle,
                          void (*cb)(const FlowKey *, const FlowValue *,
                                     void *),
                          void *ctx) {
  FlowTable *table = handle->flow_table;
  for (uint64_t i = 0; i < table->capacity; i++) {
    FlowEntry *entry = &table->entries[i];
    if (entry->state == SLOT_OCCUPIED)
      cb(&entry->key, &entry->value, ctx);
  }
}

/* ── Packet callback ──────────────────────────────────────────────── */

/* Called by pcap_loop for every captured packet. Parses headers,
 * builds a flow key, and upserts into the flow table. */
static void parse_packet(u_char *user, const struct pcap_pkthdr *header,
                         const u_char *packet) {

  if (header->caplen < sizeof(struct ether_header))
    return;

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  CaptureHandle *cap = (CaptureHandle *)user;
  FlowTable *table = cap->flow_table;

  const struct ether_header *eth_pkt = parse_ethernet(packet);

  switch (ntohs(eth_pkt->ether_type)) {
  case PKT_IPv4: {
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct iphdr))
      return;

    const struct ip *ip_pkt = parse_ip(packet);

    /* If attacker can craft a packet with header length 0 or 1
     * We protect against this with the minimum hl check */
    if (ip_pkt->ip_hl < 5)
      return;

    if (cap->verbose) {
      char src_str[INET_ADDRSTRLEN];
      char dst_str[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &ip_pkt->ip_src, src_str, sizeof(src_str));
      inet_ntop(AF_INET, &ip_pkt->ip_dst, dst_str, sizeof(dst_str));
      printf("[IPv4]  SRC: %s -> DST: %s\n", src_str, dst_str);
    }

    FlowKey key;
    FlowValue *value;
    key.src_ip = ip_pkt->ip_src.s_addr;
    key.dst_ip = ip_pkt->ip_dst.s_addr;

    switch (ip_pkt->ip_p) {
    case IPPROTO_TCP: {
      if (header->caplen < sizeof(struct ether_header) + ip_pkt->ip_hl * 4 +
                               sizeof(struct tcphdr))
        return;
      const struct tcphdr *tcp = parse_tcp(packet, ip_pkt);
      key.protocol = IPPROTO_TCP;
      key.src_port = tcp->th_sport;
      key.dst_port = tcp->th_dport;
      if (cap->verbose)
        printf("[TCP]   SRC: %u -> DST: %u\n", ntohs(tcp->th_sport),
               ntohs(tcp->th_dport));
      value = flowtable_put(table, key, now);
      if (!value)
        return;

      break;
    }
    case IPPROTO_UDP: {
      if (header->caplen < sizeof(struct ether_header) + ip_pkt->ip_hl * 4 +
                               sizeof(struct udphdr))
        return;

      const struct udphdr *udp = parse_udp(packet, ip_pkt);
      key.protocol = IPPROTO_UDP;
      key.src_port = udp->uh_sport;
      key.dst_port = udp->uh_dport;
      if (cap->verbose)
        printf("[UDP]   SRC: %u -> DST: %u\n", ntohs(udp->uh_sport),
               ntohs(udp->uh_dport));
      value = flowtable_put(table, key, now);
      if (!value)
        return;

      break;
    }
    default:
      return;
    }

    /* Update flow counters */
    value->sent_packets++;
    value->total_bytes += header->len;

    if (cap->buffer) {
      PacketEvent ev = {
          .key = key, .packet_len = header->len, .timestamp = now};
      ringbuf_push(cap->buffer, ev);
    }
    if (cap->verbose)
      printf("[FLOW]  count: %" PRIu64 "\n", table->count);
    break;
  }
  default:
    break;
  }
}

/* ── Lifecycle ────────────────────────────────────────────────────── */

/* Allocate arena, flow table, and open a live pcap handle.
 * Returns NULL on failure (error message written to config->errbuf). */
CaptureHandle *capture_open(CaptureConfig *config) {
  Arena *arena = arena_init(ARENA_SIZE);
  if (!arena)
    return NULL;

  FlowTable *flow_table = flowtable_init(arena, TABLE_CAPACITY);
  if (!flow_table) {
    arena_free(arena);
    return NULL;
  }

  pcap_t *pcap_handle = pcap_open_live(
      config->interface_name, config->snapshot_length, config->promiscuous,
      config->capture_timeout, config->errbuf);
  if (!pcap_handle) {
    arena_free(arena);
    return NULL;
  }

  CaptureHandle *handle = arena_alloc(arena, sizeof(CaptureHandle));
  if (!handle) {
    pcap_close(pcap_handle);
    arena_free(arena);
    return NULL;
  }
  handle->arena = arena;
  handle->flow_table = flow_table;
  handle->pcap = pcap_handle;
  handle->verbose = config->verbose;
  handle->buffer = NULL;

  return handle;
}

/* Signal pcap_loop to break out of its blocking read */
void capture_stop(CaptureHandle *handle) { pcap_breakloop(handle->pcap); }

/* Enter the capture loop — blocks until capture_stop or error */
int capture_start(CaptureHandle *handle) {
  return pcap_loop(handle->pcap, -1, parse_packet, (u_char *)handle);
}

/* Release pcap handle and free the arena (all allocations with it) */
void capture_close(CaptureHandle *handle) {
  pcap_close(handle->pcap);
  Arena *arena = handle->arena;
  arena_free(arena);
}

/* ── Device enumeration ───────────────────────────────────────────── */

/* Copy the first available interface name into the caller's buffer.
 * Returns 0 on success, -1 on failure (error in errbuf). */
int capture_default_device(char *name, size_t len, char *errbuf) {
  pcap_if_t *devs;
  if (pcap_findalldevs(&devs, errbuf) == -1 || !devs) {
    return -1;
  }
  snprintf(name, len, "%s", devs->name);
  pcap_freealldevs(devs);
  return 0;
}

void capture_attach_ringbuf(CaptureHandle *handle, RingBuf *rb) {
  handle->buffer = rb;
}
