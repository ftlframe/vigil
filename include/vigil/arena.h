#pragma once
#include <stddef.h>

/* Bump allocator — one malloc at init, then pointer bumps only.
 * Never grows; never frees individual objects. */
typedef struct {
    void* base_ptr;  /* Start of the memory pool */
    size_t size;     /* Total pool capacity in bytes */
    size_t offset;   /* Next free byte (bump pointer) */
} Arena;

Arena* arena_init(size_t size);
void* arena_alloc(Arena* arena, size_t size);