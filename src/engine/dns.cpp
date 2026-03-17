/*
 * dns.cpp — DNS wire format parser (RFC 1035 §4).
 *
 * Parses the 12-byte fixed header, question section, and answer RRs
 * from a raw UDP payload. Handles label compression (§4.1.4) in both
 * question names and answer names/RDATA.
 */

#include "dns.hpp"

#include <arpa/inet.h>
#include <cstring>

/* RFC 1035 §4.1.1 — Fixed header is always 12 bytes */
static constexpr uint16_t DNS_HDR_SIZE = 12;

/* RFC 1035 §2.3.4 — Max domain name length */
static constexpr size_t DNS_MAX_NAME = 253;

/* RFC 1035 §4.1.4 — Compression pointer mask */
static constexpr uint8_t LABEL_PTR_MASK = 0xC0;

/* DNS record types we decode RDATA for */
static constexpr uint16_t TYPE_A = 1;
static constexpr uint16_t TYPE_CNAME = 5;
static constexpr uint16_t TYPE_TXT = 16;
static constexpr uint16_t TYPE_AAAA = 28;

/* ── Name decoding ────────────────────────────────────────────────── */

/* Decode a DNS domain name starting at payload[offset].
 *
 * DNS names are encoded as a sequence of length-prefixed labels:
 *   \x07example\x03com\x00  →  "example.com"
 *
 * Labels may also be compression pointers (two bytes, top 2 bits set)
 * that reference an earlier position in the packet (§4.1.4).
 *
 * Returns the decoded dotted name in `out` and advances `offset`
 * past the name field. Returns false on malformed input. */
static bool decode_name(const uint8_t *payload, uint16_t len, size_t &offset,
                        std::string &out) {
  out.clear();
  size_t pos = offset;
  bool followed_ptr = false;
  size_t end_offset = 0; /* where to resume after pointer */
  int jumps = 0;

  while (pos < len) {
    /* Guard against infinite compression loops */
    if (++jumps > 128)
      return false;

    uint8_t label_len = payload[pos];

    if (label_len == 0) {
      /* Root label — end of name */
      pos++;
      break;
    }

    if ((label_len & LABEL_PTR_MASK) == LABEL_PTR_MASK) {
      /* Compression pointer: 14-bit offset into the packet */
      if (pos + 1 >= len)
        return false;
      uint16_t ptr = ((label_len & ~LABEL_PTR_MASK) << 8) | payload[pos + 1];
      if (ptr >= len)
        return false;
      if (!followed_ptr)
        end_offset = pos + 2;
      followed_ptr = true;
      pos = ptr;
      continue;
    }

    /* Regular label */
    pos++;
    if (pos + label_len > len)
      return false;
    if (out.size() + label_len + 1 > DNS_MAX_NAME)
      return false;
    if (!out.empty())
      out += '.';
    out.append(reinterpret_cast<const char *>(payload + pos), label_len);
    pos += label_len;
  }

  offset = followed_ptr ? end_offset : pos;
  return true;
}

/* ── RDATA decoding ───────────────────────────────────────────────── */

/* Decode RDATA into a human-readable string based on record type. */
static std::string decode_rdata(uint16_t type, const uint8_t *payload,
                                uint16_t pkt_len, size_t rdata_offset,
                                uint16_t rdlength) {
  if (type == TYPE_A && rdlength == 4) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, payload + rdata_offset, buf, sizeof(buf));
    return buf;
  }

  if (type == TYPE_AAAA && rdlength == 16) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, payload + rdata_offset, buf, sizeof(buf));
    return buf;
  }

  if (type == TYPE_CNAME) {
    std::string name;
    size_t off = rdata_offset;
    if (decode_name(payload, pkt_len, off, name))
      return name;
    return "<malformed>";
  }

  if (type == TYPE_TXT && rdlength > 0) {
    /* TXT RDATA: one or more length-prefixed strings */
    std::string result;
    size_t pos = rdata_offset;
    size_t end = rdata_offset + rdlength;
    while (pos < end && pos < pkt_len) {
      uint8_t slen = payload[pos++];
      if (pos + slen > end || pos + slen > pkt_len)
        break;
      if (!result.empty())
        result += ' ';
      result.append(reinterpret_cast<const char *>(payload + pos), slen);
      pos += slen;
    }
    return result;
  }

  return "<raw:" + std::to_string(rdlength) + "B>";
}

/* ── Public API ───────────────────────────────────────────────────── */

std::optional<DnsEvent> dns_parse(const uint8_t *payload, uint16_t len) {
  if (!payload || len < DNS_HDR_SIZE)
    return std::nullopt;

  DnsEvent ev{};

  /* ── Header (§4.1.1) ──────────────────────────────────────────── */
  ev.id = ntohs(*reinterpret_cast<const uint16_t *>(payload));

  uint16_t flags = ntohs(*reinterpret_cast<const uint16_t *>(payload + 2));
  ev.is_response = (flags >> 15) & 1;          /* QR: bit 15 */
  ev.rcode = flags & 0x0F;                     /* RCODE: bits 0-3 */

  uint16_t qdcount = ntohs(*reinterpret_cast<const uint16_t *>(payload + 4));
  uint16_t ancount = ntohs(*reinterpret_cast<const uint16_t *>(payload + 6));

  /* We only handle standard queries with exactly 1 question */
  if (qdcount != 1)
    return std::nullopt;

  /* ── Question section (§4.1.2) ────────────────────────────────── */
  size_t offset = DNS_HDR_SIZE;

  if (!decode_name(payload, len, offset, ev.qname))
    return std::nullopt;

  /* QTYPE (2 bytes) + QCLASS (2 bytes) */
  if (offset + 4 > len)
    return std::nullopt;
  ev.qtype = ntohs(*reinterpret_cast<const uint16_t *>(payload + offset));
  offset += 4; /* skip QTYPE + QCLASS */

  /* ── Answer section (§4.1.3) ──────────────────────────────────── */
  for (uint16_t i = 0; i < ancount && offset < len; i++) {
    /* Skip answer NAME */
    std::string aname;
    if (!decode_name(payload, len, offset, aname))
      break;

    /* TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes */
    if (offset + 10 > len)
      break;

    uint16_t rtype = ntohs(*reinterpret_cast<const uint16_t *>(payload + offset));
    uint16_t rdlength =
        ntohs(*reinterpret_cast<const uint16_t *>(payload + offset + 8));
    offset += 10;

    if (offset + rdlength > len)
      break;

    ev.answers.push_back({
        .type = rtype,
        .data = decode_rdata(rtype, payload, len, offset, rdlength),
    });

    offset += rdlength;
  }

  return ev;
}
