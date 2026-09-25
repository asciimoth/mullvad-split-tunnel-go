#pragma once

#include <cstdint>

typedef union in6_addr {
    std::uint8_t bytes[16];
    std::uint16_t words[8];
} IN6_ADDR;
