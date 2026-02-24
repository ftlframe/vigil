#pragma once
#include <stddef.h>

typedef struct {
    void* base_ptr;  // Pointer to memory start
    size_t size;     // Total size
    size_t offset;   // Current position
} Arena;

Arena* arena_init(size_t size);
void* arena_alloc(Arena* arena, size_t size);