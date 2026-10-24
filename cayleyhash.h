#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

void cayleyHash(
    const uint8_t* data,
    size_t len,
    uint8_t* out
);

void initializeCayleyHashModulus();

uint64_t getCayleyHashModulus();

void setCayleyHashModulus(uint64_t modulus);

void saveCayleyHashModulus(
    const std::string& filename
);

uint64_t loadCayleyHashModulus(
    const std::string& filename
);