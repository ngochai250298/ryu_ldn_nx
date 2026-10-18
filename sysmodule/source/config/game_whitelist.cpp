/**
 * @file game_whitelist.cpp
 * @brief LDN Game Whitelist
 *
 * Loads the whitelist once at startup and stores in a static array.
 * No file operations during MITM ShouldMitm calls.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include "game_whitelist.hpp"
#include "whitelist_parser.hpp"
#include "../debug/log.hpp"

#include <stratosphere.hpp>
#include <cstring>
#include <new>

namespace ryu_ldn::config {

namespace {

constexpr const char* WHITELIST_PATH = "sdmc:/config/ryu_ldn_nx/gamelist.txt";

// Hard cap on stored entries (8 bytes each) so a huge file cannot eat the shared heap
constexpr size_t MAX_ENTRIES = 8192;

// Dynamically allocated whitelist (sized based on file)
static u64* g_whitelist = nullptr;
static size_t g_whitelist_capacity = 0;
static size_t g_whitelist_count = 0;
static bool g_whitelist_loaded = false;

}  // namespace

void LoadWhitelist() {
    if (g_whitelist_loaded) {
        LOG_INFO("GameWhitelist: already loaded (%zu games)", g_whitelist_count);
        return;
    }

    LOG_INFO("GameWhitelist: loading from %s", WHITELIST_PATH);

    // Open the file
    ams::fs::FileHandle file;
    ams::Result rc = ams::fs::OpenFile(std::addressof(file), WHITELIST_PATH, ams::fs::OpenMode_Read);

    if (R_FAILED(rc)) {
        LOG_WARN("GameWhitelist: Cannot open %s (rc=0x%x)", WHITELIST_PATH, rc.GetValue());
        g_whitelist_loaded = true;  // Mark as loaded (empty)
        return;
    }

    // Get file size
    s64 file_size = 0;
    rc = ams::fs::GetFileSize(std::addressof(file_size), file);
    if (R_FAILED(rc) || file_size <= 0) {
        ams::fs::CloseFile(file);
        LOG_WARN("GameWhitelist: file empty or error");
        g_whitelist_loaded = true;
        return;
    }

    LOG_INFO("GameWhitelist: file_size=%lld bytes", file_size);

    // Pass 1 counts valid entries so the allocation is exact; pass 2 stores them.
    constexpr size_t CHUNK_SIZE = 512;
    char chunk[CHUNK_SIZE];

    for (int pass = 0; pass < 2; pass++) {
        WhitelistScanner scanner;
        size_t count = 0;
        auto emit = [&](u64 id) {
            if (pass == 1 && count < g_whitelist_capacity) g_whitelist[count] = id;
            count++;
        };

        for (s64 offset = 0; offset < file_size;) {
            size_t to_read = static_cast<size_t>(
                (file_size - offset) < static_cast<s64>(CHUNK_SIZE)
                ? (file_size - offset) : static_cast<s64>(CHUNK_SIZE));
            size_t bytes_read = 0;
            rc = ams::fs::ReadFile(std::addressof(bytes_read), file, offset, chunk, to_read);
            if (R_FAILED(rc) || bytes_read == 0) {
                LOG_WARN("GameWhitelist: ReadFile failed rc=0x%x", rc.GetValue());
                break;
            }
            scanner.Feed(chunk, bytes_read, emit);
            offset += bytes_read;
        }
        scanner.Finish(emit);

        if (pass == 0) {
            if (count > MAX_ENTRIES) {
                LOG_WARN("GameWhitelist: %zu entries, keeping the first %zu", count, MAX_ENTRIES);
                count = MAX_ENTRIES;
            }
            g_whitelist_capacity = count;
            if (count == 0) break;
            g_whitelist = new (std::nothrow) u64[count];
            if (!g_whitelist) {
                g_whitelist_capacity = 0;
                LOG_ERROR("GameWhitelist: failed to allocate %zu entries", count);
                break;
            }
            LOG_INFO("GameWhitelist: allocated %zu entries", count);
        } else {
            g_whitelist_count = count < g_whitelist_capacity ? count : g_whitelist_capacity;
        }
    }

    ams::fs::CloseFile(file);
    g_whitelist_loaded = true;

    LOG_INFO("GameWhitelist: loaded %zu games", g_whitelist_count);
}

bool IsGameInWhitelist(u64 program_id) {
    if (!g_whitelist_loaded) {
        LOG_WARN("GameWhitelist: not loaded yet!");
        return false;
    }

    // Simple linear search (fast enough for ~5000 entries)
    for (size_t i = 0; i < g_whitelist_count; i++) {
        if (g_whitelist[i] == program_id) {
            return true;
        }
    }

    return false;
}

}  // namespace ryu_ldn::config
