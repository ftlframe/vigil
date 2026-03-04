#pragma once
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/* Layer-by-layer header extraction from a raw captured frame.
 * Each function returns a const pointer into the packet buffer at the
 * correct offset — no copies, no allocations.
 *
 * Preconditions: callers must validate caplen against minimum header
 * sizes before calling. None of these functions perform bounds checking. */

const struct ether_header *parse_ethernet(const u_char *raw_pkt);
const struct ip *parse_ip(const u_char *raw_pkt);
const struct tcphdr *parse_tcp(const u_char *raw_pkt, const struct ip *ip_pkt);
const struct udphdr *parse_udp(const u_char *raw_pkt, const struct ip *ip_pkt);
