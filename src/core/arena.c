#include "vigil/arena.h"

#include <stdlib.h>

#define ALIGN sizeof(void*)

Arena* arena_init(size_t size) {
    // Single allocation: Arena struct + pool in one contiguous block
    Arena* arena_ptr = malloc(sizeof(Arena) + size);
    if (!arena_ptr) return NULL;

    // Pool starts right after the struct
    arena_ptr->base_ptr = (char*)arena_ptr + sizeof(Arena);
    arena_ptr->size = size;
    arena_ptr->offset = 0;

    return arena_ptr;
}

void* arena_alloc(Arena* arena, size_t size) {
    // Round offset up to nearest aligned boundary
    arena->offset = (arena->offset + (ALIGN - 1)) & ~(ALIGN - 1);

    // Bounds check after alignment
    if (arena->offset + size > arena->size) return NULL;

    // Save current position, then bump
    void* ptr = (char*)arena->base_ptr + arena->offset;
    arena->offset += size;
    return ptr;
}