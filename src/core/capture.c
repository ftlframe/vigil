#include "vigil/capture.h"

#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

#include "vigil/hashmap.h"
#include "vigil/parse.h"

/* Capture config */
#define ARENA_SIZE (1024 * 256) /* 256KB */
#define TABLE_CAPACITY 1024

/* EtherType constants */
#define PKT_IPv4 0x0800
#define PKT_ARP 0x0806
#define PKT_IPv6 0x86DD

/* ── Packet callback ───────────────────────────────────────────────── */

static void parse_packet(
    u_char* user, const struct pcap_pkthdr* header, const u_char* packet
) {
    CaptureHandle* cap = (CaptureHandle*)user;
    FlowTable* table = cap->flow_table;
    struct ether_header* eth_pkt = parse_ethernet(packet);

    switch (ntohs(eth_pkt->ether_type)) {
        case PKT_IPv4: {
            struct ip* ip_pkt = parse_ip(packet);

            if (cap->verbose) {
                printf("[IPv4]  SRC: %s", inet_ntoa(ip_pkt->ip_src));
                printf(" -> DST: %s\n", inet_ntoa(ip_pkt->ip_dst));
            }

            /* Zero padding bytes so memcmp doesn't mismatch on
             * garbage between struct fields */
            FlowKey key;
            memset(&key, 0, sizeof(FlowKey));
            key.src_ip = ip_pkt->ip_src.s_addr;
            key.dst_ip = ip_pkt->ip_dst.s_addr;

            switch (ip_pkt->ip_p) {
                case IPPROTO_TCP: {
                    struct tcphdr* tcp = parse_tcp(packet, ip_pkt);
                    key.protocol = IPPROTO_TCP;
                    key.src_port = tcp->th_sport;
                    key.dst_port = tcp->th_dport;
                    if (cap->verbose)
                        printf("[TCP]   SRC: %d -> DST: %d\n",
                            ntohs(tcp->th_sport), ntohs(tcp->th_dport));
                    break;
                }
                case IPPROTO_UDP: {
                    struct udphdr* udp = parse_udp(packet, ip_pkt);
                    key.protocol = IPPROTO_UDP;
                    key.src_port = udp->uh_sport;
                    key.dst_port = udp->uh_dport;
                    if (cap->verbose)
                        printf("[UDP]   SRC: %d -> DST: %d\n",
                            ntohs(udp->uh_sport), ntohs(udp->uh_dport));
                    break;
                }
                default:
                    break;
            }

            flowtable_put(table, key);
            if (cap->verbose)
                printf("[FLOW]  count: %lu\n", table->count);
            break;
        }
        default:
            break;
    }
}

CaptureHandle* capture_open(CaptureConfig* config) {
    Arena* arena = arena_init(ARENA_SIZE);
    if (!arena) return NULL;

    FlowTable* flow_table = flowtable_init(arena, TABLE_CAPACITY);
    if (!flow_table) {
        arena_free(arena);
        return NULL;
    }

    pcap_t* pcap_handle = pcap_open_live(
        config->interface_name, config->snapshot_length, config->promiscuous,
        config->capture_timeout, config->errbuf
    );
    if (!pcap_handle) {
        arena_free(arena);
        return NULL;
    }

    CaptureHandle* handle = arena_alloc(arena, sizeof(CaptureHandle));
    if (!handle) {
        arena_free(arena);
        return NULL;
    }
    handle->arena = arena;
    handle->flow_table = flow_table;
    handle->pcap = pcap_handle;
    handle->verbose = config->verbose;

    return handle;
}

void capture_stop(CaptureHandle* handle) { pcap_breakloop(handle->pcap); }

int capture_start(CaptureHandle* handle) {
    return pcap_loop(
        handle->pcap, -1, parse_packet, (u_char*)handle
    );
}
void capture_close(CaptureHandle* handle) {
    pcap_close(handle->pcap);
    arena_free(handle->arena);
}
