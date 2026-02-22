#include "vigil/parse.h"

struct ether_header* parse_ethernet(const u_char* raw_pkt) {
    return (struct ether_header*)raw_pkt;
}

struct ip* parse_ip(const u_char* raw_pkt) {
    return (struct ip*)(raw_pkt + sizeof(struct ether_header));
}

struct tcphdr* parse_tcp(const u_char* raw_pkt, const struct ip* ip_pkt) {
    return (struct tcphdr*)(raw_pkt + sizeof(struct ether_header) +
                            (ip_pkt->ip_hl) * 4);
}
struct udphdr* parse_udp(const u_char* raw_pkt, const struct ip* ip_pkt) {
    return (struct udphdr*)(raw_pkt + sizeof(struct ether_header) +
                            (ip_pkt->ip_hl) * 4);
}