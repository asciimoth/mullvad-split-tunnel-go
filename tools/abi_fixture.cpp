// Rebuild with a checked-out, pinned mullvad/win-split-tunnel source tree:
// g++ -std=c++17 -I /path/to/win-split-tunnel/src tools/abi_fixture.cpp -o abi-fixture
// ./abi-fixture > testdata/abi.json
//
// Windows x64/ARM64 scalar aliases let the actual upstream protocol headers
// be inspected on a 64-bit development host. This is a layout check, not a
// substitute for compiling against the WDK or exercising a live Windows driver.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using SIZE_T = std::uint64_t;
using HANDLE = void*;
using USHORT = std::uint16_t;
using BOOLEAN = std::uint8_t;
using UCHAR = std::uint8_t;
using WCHAR = char16_t;
using NTSTATUS = std::int32_t;
struct GUID {
    std::uint32_t Data1;
    std::uint16_t Data2, Data3;
    std::uint8_t Data4[8];
};
#define ANYSIZE_ARRAY 1
#define METHOD_BUFFERED 0
#define METHOD_NEITHER 3
#define FILE_ANY_ACCESS 0
#define CTL_CODE(d, f, m, a) ((std::uint32_t(d) << 16) | ((a) << 14) | ((f) << 2) | (m))
#include "defs/config.h"
#include "defs/process.h"
#include "defs/queryprocess.h"
#include "defs/events.h"
#include "defs/sublayer.h"
#include "defs/state.h"
#include "defs/ioctl.h"

static_assert(sizeof(void*) == 8);
static_assert(sizeof(WCHAR) == 2);
static_assert(sizeof(ST_CONFIGURATION_HEADER) == 16);
static_assert(sizeof(ST_CONFIGURATION_ENTRY) == 16);
static_assert(sizeof(ST_PROCESS_DISCOVERY_ENTRY) == 32);
static_assert(sizeof(ST_QUERY_PROCESS_RESPONSE) == 24);
static_assert(offsetof(ST_QUERY_PROCESS_RESPONSE, ImageName) == 20);
static_assert(offsetof(ST_EVENT_HEADER, EventData) == 16);
static_assert(offsetof(ST_SPLITTING_EVENT, ImageName) == 14);
static_assert(offsetof(ST_SPLITTING_ERROR_EVENT, ImageName) == 10);
static_assert(offsetof(ST_ERROR_MESSAGE_EVENT, ErrorMessage) == 6);
static_assert(sizeof(ST_SUBLAYER_GUIDS) == 32);
static_assert(ST_DRIVER_STATE_ZOMBIE == 5);

std::string hex(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream out;
    for (auto byte : bytes)
        out << std::hex << std::setfill('0') << std::setw(2) << unsigned(byte);
    return out.str();
}
template<typename T>
void copy(std::vector<std::uint8_t>& out, std::size_t offset, const T& value) {
    std::memcpy(out.data() + offset, &value, sizeof(value));
}
void name(std::vector<std::uint8_t>& out, std::size_t offset, const std::u16string& value) {
    std::memcpy(out.data() + offset, value.data(), value.size() * 2);
}

int main() {
    const std::vector<std::u16string> paths{
        u"\\Device\\X\\app.exe", u"\\Device\\X\\\u03b2\U0001f98b.exe"
    };
    const auto first = paths[0].size() * 2;
    const auto start = sizeof(ST_CONFIGURATION_HEADER) + paths.size() * sizeof(ST_CONFIGURATION_ENTRY);
    std::vector<std::uint8_t> config(start + first + paths[1].size() * 2, 0);
    ST_CONFIGURATION_HEADER ch{paths.size(), config.size()};
    copy(config, 0, ch);
    std::size_t cursor = 0;
    for (std::size_t i = 0; i < paths.size(); i++) {
        ST_CONFIGURATION_ENTRY entry{};
        entry.ImageNameOffset = cursor;
        entry.ImageNameLength = paths[i].size() * 2;
        copy(config, sizeof(ch) + i * sizeof(entry), entry);
        name(config, start + cursor, paths[i]);
        cursor += paths[i].size() * 2;
    }
    std::vector<std::uint8_t> processes(sizeof(ST_PROCESS_DISCOVERY_HEADER) +
        sizeof(ST_PROCESS_DISCOVERY_ENTRY) + first, 0);
    ST_PROCESS_DISCOVERY_HEADER ph{1, processes.size()};
    ST_PROCESS_DISCOVERY_ENTRY pe{};
    pe.ProcessId = reinterpret_cast<HANDLE>(42);
    pe.ParentProcessId = reinterpret_cast<HANDLE>(7);
    pe.ImageNameLength = first;
    copy(processes, 0, ph);
    copy(processes, sizeof(ph), pe);
    name(processes, sizeof(ph) + sizeof(pe), paths[0]);

    const auto eventStart = offsetof(ST_EVENT_HEADER, EventData);
    const auto eventName = offsetof(ST_SPLITTING_EVENT, ImageName);
    std::vector<std::uint8_t> event(eventStart + eventName + first, 0);
    ST_EVENT_HEADER eh{};
    eh.EventId = ST_EVENT_ID_START_SPLITTING_PROCESS;
    eh.EventSize = eventName + first;
    std::memcpy(event.data(), &eh, eventStart);
    ST_SPLITTING_EVENT se{};
    se.ProcessId = reinterpret_cast<HANDLE>(42);
    se.Reason = static_cast<ST_SPLITTING_STATUS_CHANGE_REASON>(
        ST_SPLITTING_REASON_BY_CONFIG | ST_SPLITTING_REASON_PROCESS_ARRIVING);
    se.ImageNameLength = first;
    std::memcpy(event.data() + eventStart, &se, eventName);
    name(event, eventStart + eventName, paths[0]);

    // Match the driver's sizeof(response)-sizeof(ImageName)+length formula.
    const auto queryName = offsetof(ST_QUERY_PROCESS_RESPONSE, ImageName);
    std::vector<std::uint8_t> query(sizeof(ST_QUERY_PROCESS_RESPONSE) - sizeof(WCHAR) + first, 0);
    ST_QUERY_PROCESS_RESPONSE qr{};
    qr.ProcessId = reinterpret_cast<HANDLE>(42);
    qr.ParentProcessId = reinterpret_cast<HANDLE>(7);
    qr.Split = 1;
    qr.ImageNameLength = first;
    std::memcpy(query.data(), &qr, queryName);
    name(query, queryName, paths[0]);

    ST_SUBLAYER_GUIDS sg{
        {0x00112233, 0x4455, 0x6677, {0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff}},
        {0xffeeddcc, 0xbbaa, 0x9988, {0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00}}
    };
    std::vector<std::uint8_t> sublayers(sizeof(sg), 0);
    copy(sublayers, 0, sg);
    std::cout << "{\n"
        << "  \"configuration\": \"" << hex(config) << "\",\n"
        << "  \"processes\": \"" << hex(processes) << "\",\n"
        << "  \"event\": \"" << hex(event) << "\",\n"
        << "  \"query\": \"" << hex(query) << "\",\n"
        << "  \"sublayers\": \"" << hex(sublayers) << "\",\n"
        << "  \"ioctls\": [" << IOCTL_ST_INITIALIZE << "," << IOCTL_ST_DEQUEUE_EVENT
        << "," << IOCTL_ST_REGISTER_PROCESSES << "," << IOCTL_ST_REGISTER_IP_ADDRESSES
        << "," << IOCTL_ST_GET_IP_ADDRESSES << "," << IOCTL_ST_SET_CONFIGURATION
        << "," << IOCTL_ST_GET_CONFIGURATION << "," << IOCTL_ST_CLEAR_CONFIGURATION
        << "," << IOCTL_ST_GET_STATE << "," << IOCTL_ST_QUERY_PROCESS
        << "," << IOCTL_ST_RESET << "]\n}\n";
}
