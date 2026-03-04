#include "vigil/parse.h"

/* Cast raw frame to Ethernet header (starts at byte 0) */
const struct ether_header *parse_ethernet(const u_char *raw_pkt) {
  return (struct ether_header *)raw_pkt;
}

/* Skip past Ethernet header to reach the IP header */
const struct ip *parse_ip(const u_char *raw_pkt) {
  return (struct ip *)(raw_pkt + sizeof(struct ether_header));
}

/* Skip Ethernet + IP headers to reach TCP/UDP.
 * ip_hl is in 32-bit words (RFC 791 §3.1), so multiply by 4 for bytes.
 * IP header ranges from 20B (ip_hl=5) to 60B (ip_hl=15). */
const struct tcphdr *parse_tcp(const u_char *raw_pkt, const struct ip *ip_pkt) {
  return (struct tcphdr *)(raw_pkt + sizeof(struct ether_header) +
                           (ip_pkt->ip_hl) * 4);
}

/* Same offset calculation as TCP */
const struct udphdr *parse_udp(const u_char *raw_pkt, const struct ip *ip_pkt) {
  return (struct udphdr *)(raw_pkt + sizeof(struct ether_header) +
                           (ip_pkt->ip_hl) * 4);
}
