#ifndef CAYLEYHASH_H
#define CAYLEYHASH_H

#include <cstddef>
#include <cstdint>

void cayleyHash(
    const uint8_t* data,
    size_t len,
    uint8_t* out
);

#endif