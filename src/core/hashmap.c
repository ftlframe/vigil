#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "vigil/hashmap.h"

/* FNV-1a 32-bit hash constants */
#define FNV_OFFSET_BASIS 2166136261
#define FNV_PRIME 16777619

/* Seconds before an idle flow is eligible for eviction */
#define FLOW_TIMEOUT 60

/* ── Allocation ───────────────────────────────────────────────────── */

/* Allocate table + backing array from the arena, zero-initialise slots */
FlowTable *flowtable_init(Arena *arena, size_t capacity) {
  FlowTable *table = arena_alloc(arena, sizeof(FlowTable));
  if (!table)
    return NULL;

  table->entries = arena_alloc(arena, sizeof(FlowEntry) * capacity);
  if (!table->entries)
    return NULL;

  memset(table->entries, 0, sizeof(FlowEntry) * capacity);
  table->capacity = capacity;
  table->count = 0;

  return table;
}

/* ── Hashing ──────────────────────────────────────────────────────── */

/* FNV-1a over the raw bytes of a FlowKey */
uint32_t flowtable_hash(FlowKey key) {
  uint32_t hash = FNV_OFFSET_BASIS;
  for (int i = 0; i < sizeof(FlowKey); i++) {
    hash ^= ((uint8_t *)&key)[i];
    hash *= FNV_PRIME;
  }

  return hash;
}

/* ── Eviction ─────────────────────────────────────────────────────── */

/* Full table sweep: tombstone every flow idle longer than FLOW_TIMEOUT.
 * Triggered by flowtable_put when load exceeds 75%. */
void flowtable_evict(FlowTable *table) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  for (uint64_t i = 0; i < table->capacity; i++) {
    FlowEntry *entry = &table->entries[i];
    if (entry->state != SLOT_OCCUPIED)
      continue;

    long elapsed = now.tv_sec - entry->value.last_seen.tv_sec;
    if (elapsed > FLOW_TIMEOUT) {
      entry->state = SLOT_TOMBSTONE;
      table->count--;
    }
  }
}

/* ── Insert / Lookup ──────────────────────────────────────────────── */

/* Insert or update a flow. Returns pointer to the FlowValue so the
 * caller can fill in packet counts, timestamps, etc.
 * Linear probing with tombstone reuse; returns NULL when table is full. */
FlowValue *flowtable_put(FlowTable *table, FlowKey key) {
  /* Evict stale flows when load exceeds 75% (integer-only check) */
  if (table->count * 4 > table->capacity * 3)
    flowtable_evict(table);

  uint32_t hash = flowtable_hash(key);
  uint32_t index = hash & (table->capacity - 1);

  int first_tombstone = -1;
  for (uint32_t i = 0; i < table->capacity; i++) {
    uint32_t probe = (index + i) & (table->capacity - 1);
    FlowEntry *entry = &table->entries[probe];

    switch (entry->state) {
    case SLOT_EMPTY:
      /* Key not in table — insert at earliest tombstone or here */
      if (first_tombstone != -1) {
        entry = &table->entries[first_tombstone];
      }
      entry->state = SLOT_OCCUPIED;
      table->count++;
      entry->key = key;
      return &entry->value;
    case SLOT_OCCUPIED:
      if (!memcmp(&entry->key, &key, sizeof(FlowKey)))
        return &entry->value;
      continue;
    case SLOT_TOMBSTONE:
      /* Remember first reclaimable slot, but keep probing
       * to check if the key exists further down the chain */
      if (first_tombstone == -1)
        first_tombstone = probe;
      continue;
    default:
      break;
    }
  }
  return NULL;
}

/* Lookup a flow by key. Returns pointer to FlowValue or NULL.
 * Skips over tombstones; stops at the first empty slot. */
FlowValue *flowtable_get(FlowTable *table, FlowKey key) {
  uint32_t hash = flowtable_hash(key);
  uint32_t index = hash & (table->capacity - 1);

  for (uint32_t i = 0; i < table->capacity; i++) {
    uint32_t probe = (index + i) & (table->capacity - 1);
    FlowEntry *entry = &table->entries[probe];

    switch (entry->state) {
    case SLOT_EMPTY:
      return NULL;
    case SLOT_TOMBSTONE:
      continue;
    case SLOT_OCCUPIED:
      if (!memcmp(&entry->key, &key, sizeof(FlowKey)))
        return &entry->value;
      continue;
    }
  }
  return NULL;
}
