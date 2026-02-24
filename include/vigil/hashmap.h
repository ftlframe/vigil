#pragma once
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <string.h>

#include "arena.h"

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;
} FlowKey;


typedef struct {
  uint64_t sent_packets;
  uint64_t total_bytes;
  struct timeval first_seen;
  struct timeval last_seen;
} FlowValue;

typedef struct {
  FlowKey key;
  FlowValue value;
  uint8_t occupied;
} FlowEntry;

typedef struct {
  FlowEntry* entries;
  uint64_t capacity;
  uint64_t count;
} FlowTable;

FlowTable* flowtable_init(Arena* arena, size_t capacity);
FlowValue* flowtable_put(FlowTable* table, FlowKey key);
FlowValue* flowtable_get(FlowTable* table, FlowKey key);
uint32_t flowtable_hash(FlowKey key);
