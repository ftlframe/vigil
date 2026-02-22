#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <sys/types.h>

#include "vigil/parse.h"

#define SNAPLEN 262144
#define PROMISC 1
#define CAPTURE_TIMEOUT 1000  // 1s

#define PKT_IPv4 0x0800
#define PKT_ARP 0x0806
#define PKT_IPv6 0x86DD

void print_hex(const u_char* packet, const int caplen) {
    for (int i = 0; i < caplen; i++) {
        if (i % 16 == 0) printf("%04x: ", i & ~0xF);

        printf("%02x ", packet[i]);

        if (i % 16 == 15) printf("\n");
    }
    printf("\n");
}

void print_eth(const struct ether_header* eth_packet) {
    printf("[ETH]   DST: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth_packet->ether_dhost[i]);

        if (i < 5) printf(":");
    }

    printf(" -> SRC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth_packet->ether_shost[i]);

        if (i < 5) printf(":");
    }
    printf("\n");
}


/**
 * TODO: Add a flag to change the output to a oneliner later on...
 */
void parse_packet(
    u_char* user, const struct pcap_pkthdr* header, const u_char* packet
) {
    struct ether_header* eth_pkt = parse_ethernet(packet);

    print_eth(eth_pkt);

    switch (ntohs(eth_pkt->ether_type)) {
        case PKT_IPv4: {
            struct ip* ip_pkt = parse_ip(packet);
            printf("[IPv4]  SRC: %s", inet_ntoa(ip_pkt->ip_src));
            printf(" -> DST: %s\n", inet_ntoa(ip_pkt->ip_dst));
            switch (ip_pkt->ip_p) {
                case IPPROTO_TCP: {
                    struct tcphdr* seg_tcp = parse_tcp(packet, ip_pkt);
                    printf(
                        "[TCP]   PORT_SRC: %d -> PORT_DST: %d\n",
                        ntohs(seg_tcp->th_sport), ntohs(seg_tcp->th_dport)
                    );
                    break;
                }
                case IPPROTO_UDP: {
                    struct udphdr* seg_udp = parse_udp(packet, ip_pkt);
                    printf(
                        "[UDP]   PORT_SRC: %d -> PORT_DST: %d\n",
                        ntohs(seg_udp->uh_sport), ntohs(seg_udp->uh_dport)
                    );
                    break;
                }
                default:
                    break;
            }
            break;
        }

        default:
            break;
    }

    print_hex(packet, header->caplen);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle =
        pcap_open_live("enp10s0", SNAPLEN, PROMISC, CAPTURE_TIMEOUT, errbuf);
    if (!handle) {
        printf("%s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, -1, parse_packet, NULL);
    return 0;
}