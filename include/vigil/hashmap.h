#pragma once
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#include "arena.h"

/* Open-addressed hash map (linear probing) for tracking network flows.
 * All memory comes from the arena — no per-entry malloc. */

/* A state enum for lazy eviction and for the load triggered sweep */
typedef enum {
  SLOT_EMPTY = 0,
  SLOT_OCCUPIED,
  SLOT_TOMBSTONE,
} FlowKeyState;

/* 5-tuple that uniquely identifies a connection */
typedef struct FlowKey {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint8_t protocol;
  uint16_t src_port;
  uint16_t dst_port;
} FlowKey;

/* Per-flow statistics */
typedef struct FlowValue {
  uint64_t sent_packets;
  uint64_t total_bytes;
  struct timespec first_seen;
  struct timespec last_seen;
} FlowValue;

/* Single slot in the hash table */
typedef struct FlowEntry {
  FlowKey key;
  FlowValue value;
  FlowKeyState state;
} FlowEntry;

/* Top-level table handle */
typedef struct FlowTable {
  FlowEntry *entries;
  uint64_t capacity;
  uint64_t count;
} FlowTable;

FlowTable *flowtable_init(Arena *arena, size_t capacity);
FlowValue *flowtable_put(FlowTable *table, FlowKey key);
FlowValue *flowtable_get(FlowTable *table, FlowKey key);
uint32_t flowtable_hash(FlowKey key);
void flowtable_evict(FlowTable *table);
