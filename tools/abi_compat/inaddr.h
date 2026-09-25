#pragma once

#include <cstdint>

typedef union in_addr {
    std::uint32_t s_addr;
    std::uint8_t bytes[4];
} IN_ADDR;
