/*
 * protocol.hpp — Application-layer protocol types for the engine.
 *
 * Defines the parsed event structures emitted by protocol classifiers
 * (DNS, HTTP, MQTT) and consumed by the anomaly rules engine.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

/* Identifies which application-layer protocol a classifier recognized. */
enum class ProtocolID { DNS = 0, HTTP, MQTT, UNKNOWN };

/*
 * A single resource record from the answer section of a DNS response.
 * Stores the record type and its data as a human-readable string
 * (e.g., "93.184.216.34" for an A record, "example.com" for a CNAME).
 */
struct DnsRecord {
  uint16_t type;    /* RFC 1035 §3.2.2 — A=1, AAAA=28, CNAME=5, TXT=16, etc. */
  std::string data; /* Decoded RDATA: IP address, domain name, or raw text */
};

/*
 * Parsed DNS event extracted from a single query or response packet.
 *
 * The anomaly engine uses these to detect:
 *   - Queries to suspicious/known-bad domains (qname)
 *   - DNS tunneling via unusual record types (qtype: TXT, NULL)
 *   - DGA activity via NXDOMAIN response spikes (rcode)
 *   - Unexpected resolved destinations (answers)
 */
struct DnsEvent {
  uint16_t id;       /* Transaction ID — correlates queries to responses */
  bool is_response;  /* false = query, true = response (QR bit) */
  uint8_t rcode;     /* Response code — 0=NOERROR, 3=NXDOMAIN (RFC 1035 §4.1.1) */

  std::string qname; /* Queried domain name (e.g., "example.com") */
  uint16_t qtype;    /* Query type — A=1, AAAA=28, TXT=16 (RFC 1035 §3.2.2) */

  std::vector<DnsRecord> answers; /* Answer RRs (empty for queries) */
};
