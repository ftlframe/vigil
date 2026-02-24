#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <sys/types.h>

#include "vigil/arena.h"
#include "vigil/hashmap.h"
#include "vigil/parse.h"

/* Capture config */
#define SNAPLEN 262144
#define PROMISC 1
#define CAPTURE_TIMEOUT 1000     // 1s
#define ARENA_SIZE (1024 * 256)  // 256KB
#define TABLE_CAPACITY 1024

/* EtherType constants */
#define PKT_IPv4 0x0800
#define PKT_ARP 0x0806
#define PKT_IPv6 0x86DD

/* ── Printing helpers ──────────────────────────────────────────────── */

void print_hex(const u_char* packet, int caplen) {
    for (int i = 0; i < caplen; i++) {
        if (i % 16 == 0) printf("%04x: ", i & ~0xF);
        printf("%02x ", packet[i]);
        if (i % 16 == 15) printf("\n");
    }
    printf("\n");
}

void print_mac(const char* label, const uint8_t* mac) {
    printf("%s", label);
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
}

/* ── Packet callback ───────────────────────────────────────────────── */

// TODO: Add a flag to switch between verbose and oneliner output

void parse_packet(
    u_char* user, const struct pcap_pkthdr* header, const u_char* packet
) {
    FlowTable* table = (FlowTable*)user;
    struct ether_header* eth_pkt = parse_ethernet(packet);

    print_mac("[ETH]   DST: ", eth_pkt->ether_dhost);
    print_mac(" -> SRC: ", eth_pkt->ether_shost);
    printf("\n");

    switch (ntohs(eth_pkt->ether_type)) {
        case PKT_IPv4: {
            struct ip* ip_pkt = parse_ip(packet);
            printf("[IPv4]  SRC: %s", inet_ntoa(ip_pkt->ip_src));
            printf(" -> DST: %s\n", inet_ntoa(ip_pkt->ip_dst));

            // Zero padding bytes so memcmp in the hash map doesn't
            // mismatch on garbage between struct fields
            FlowKey key;
            memset(&key, 0, sizeof(FlowKey));
            key.src_ip = ip_pkt->ip_src.s_addr;
            key.dst_ip = ip_pkt->ip_dst.s_addr;

            switch (ip_pkt->ip_p) {
                case IPPROTO_TCP: {
                    struct tcphdr* tcp = parse_tcp(packet, ip_pkt);
                    printf(
                        "[TCP]   PORT_SRC: %d -> PORT_DST: %d\n",
                        ntohs(tcp->th_sport), ntohs(tcp->th_dport)
                    );
                    key.protocol = IPPROTO_TCP;
                    key.src_port = tcp->th_sport;
                    key.dst_port = tcp->th_dport;
                    break;
                }
                case IPPROTO_UDP: {
                    struct udphdr* udp = parse_udp(packet, ip_pkt);
                    printf(
                        "[UDP]   PORT_SRC: %d -> PORT_DST: %d\n",
                        ntohs(udp->uh_sport), ntohs(udp->uh_dport)
                    );
                    key.protocol = IPPROTO_UDP;
                    key.src_port = udp->uh_sport;
                    key.dst_port = udp->uh_dport;
                    break;
                }
                default:
                    break;
            }

            flowtable_put(table, key);
            printf("[FLOW] count: %lu\n", table->count);
            break;
        }
        default:
            break;
    }
}

/* ── Entry point ───────────────────────────────────────────────────── */

int main() {
    Arena* arena = arena_init(ARENA_SIZE);
    FlowTable* flow_table = flowtable_init(arena, TABLE_CAPACITY);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle =
        pcap_open_live("enp10s0", SNAPLEN, PROMISC, CAPTURE_TIMEOUT, errbuf);
    if (!handle) {
        fprintf(stderr, "%s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, -1, parse_packet, (u_char*)flow_table);
    return 0;
}
