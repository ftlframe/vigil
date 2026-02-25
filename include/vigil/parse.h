#pragma once
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/* Layer-by-layer header extraction from a raw captured frame.
 * Each function returns a pointer into the packet buffer at the
 * correct offset — no copies, no allocations. */

struct ether_header* parse_ethernet(const u_char* raw_pkt);
struct ip* parse_ip(const u_char* raw_pkt);
struct tcphdr* parse_tcp(const u_char* raw_pkt, const struct ip* ip_pkt);
struct udphdr* parse_udp(const u_char* raw_pkt, const struct ip* ip_pkt);