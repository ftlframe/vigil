#include <stdlib.h>
#include <string.h>

#include "vigil/hashmap.h"

/* FNV-1a 32-bit hash constants */
#define FNV_OFFSET_BASIS 2166136261
#define FNV_PRIME 16777619

/* Allocate table + entries from the arena, zero-initialise slots */
FlowTable* flowtable_init(Arena* arena, size_t capacity) {
    FlowTable* table = arena_alloc(arena, sizeof(FlowTable));
    if (!table) return NULL;

    table->entries = arena_alloc(arena, sizeof(FlowEntry) * capacity);
    if (!table->entries) return NULL;

    memset(table->entries, 0, sizeof(FlowEntry) * capacity);
    table->capacity = capacity;
    table->count = 0;

    return table;
}

/* FNV-1a over the raw bytes of a FlowKey */
uint32_t flowtable_hash(FlowKey key) {
    uint32_t hash = FNV_OFFSET_BASIS;
    for (int i = 0; i < sizeof(FlowKey); i++) {
        hash ^= ((uint8_t*)&key)[i];
        hash *= FNV_PRIME;
    }

    return hash;
}

/* Insert or retrieve — returns pointer to the value for this key.
 * Linear probing; returns NULL only when the table is full. */
FlowValue* flowtable_put(FlowTable* table, FlowKey key) {
    uint32_t hash = flowtable_hash(key);
    uint32_t index = hash & (table->capacity - 1);

    for (uint32_t i = 0; i < table->capacity; i++) {
        uint32_t probe = (index + i) & (table->capacity - 1);
        FlowEntry* entry = &table->entries[probe];

        if (!entry->occupied) {
            entry->occupied = 1;
            table->count++;
            entry->key = key;
            return &entry->value;
        } else if (entry->occupied &&
                   !memcmp(&entry->key, &key, sizeof(FlowKey))) {
            return &entry->value;
        }
    }

    return NULL;
}

/* Lookup — returns pointer to value if found, NULL otherwise */
FlowValue* flowtable_get(FlowTable* table, FlowKey key) {
    uint32_t hash = flowtable_hash(key);
    uint32_t index = hash & (table->capacity - 1);

    for (uint32_t i = 0; i < table->capacity; i++) {
        uint32_t probe = (index + i) & (table->capacity - 1);
        FlowEntry* entry = &table->entries[probe];

        if (!entry->occupied)
            return NULL;
        else if (!memcmp(&entry->key, &key, sizeof(FlowKey)))
            return &entry->value;
    }

    return NULL;
}