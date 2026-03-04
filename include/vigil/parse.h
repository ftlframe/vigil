#pragma once
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/* Layer-by-layer header extraction from a raw captured frame.
 * Each function returns a pointer into the packet buffer at the
 * correct offset — no copies, no allocations.
 *
 * TODO: document preconditions — callers must validate caplen
 *       against minimum header sizes before calling these functions.
 * TODO: return const pointers (const struct ether_header*, etc.)
 *       to preserve const-correctness from the input buffer.
 *       Enable -Wcast-qual to catch this class of issue. */

struct ether_header* parse_ethernet(const u_char* raw_pkt);
struct ip* parse_ip(const u_char* raw_pkt);
struct tcphdr* parse_tcp(const u_char* raw_pkt, const struct ip* ip_pkt);
struct udphdr* parse_udp(const u_char* raw_pkt, const struct ip* ip_pkt);