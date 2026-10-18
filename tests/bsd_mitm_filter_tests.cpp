/**
 * @file bsd_mitm_filter_tests.cpp
 * @brief Unit tests for the bsd:u MITM program filter (BsdMitmService::ShouldMitm)
 *
 * ShouldMitm skips our own sysmodule and every non-application program, then
 * defers to the LDN game whitelist. The application check uses
 * ncm::IsApplicationId from libstratosphere, which cannot be built on the
 * host, so its range is mirrored here from
 * Atmosphere-libs/libstratosphere/include/stratosphere/ncm/ncm_content_meta_id.hpp.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include <cstdio>
#include <cstdint>
#include <cstdlib>

// ============================================================================
// Test Framework (minimal)
// ============================================================================

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST(name) \
    static void test_##name(); \
    static struct test_##name##_register { \
        test_##name##_register() { \
            printf("  [TEST] %s... ", #name); \
            fflush(stdout); \
            int failed_before = g_tests_failed; \
            test_##name(); \
            if (g_tests_failed == failed_before) { \
                printf("PASS\n"); \
                g_tests_passed++; \
            } \
        } \
    } test_##name##_instance; \
    static void test_##name()

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            printf("FAIL\n    Assertion failed: %s\n    at %s:%d\n", #cond, __FILE__, __LINE__); \
            g_tests_failed++; \
            return; \
        } \
    } while(0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

// ============================================================================
// Filter (mirrors BsdMitmService::ShouldMitm, minus the first-session skip)
// ============================================================================

using u64 = uint64_t;

// ncm::ApplicationId::Start / End
constexpr u64 APPLICATION_ID_START = 0x0100000000010000ULL;
constexpr u64 APPLICATION_ID_END   = 0x01FFFFFFFFFFFFFFULL;

constexpr u64 OUR_PROGRAM_ID = 0x4200000000000010ULL;

constexpr bool IsApplicationId(u64 program_id) {
    return APPLICATION_ID_START <= program_id && program_id <= APPLICATION_ID_END;
}

// Stand-in whitelist: two real entries from config/ryu_ldn_nx/gamelist.txt
static bool IsGameInWhitelist(u64 program_id) {
    return program_id == 0x0100C2500FC20000ULL    // Splatoon 3
        || program_id == 0x0100000011D90000ULL;   // Pokemon Brilliant Diamond
}

static bool ShouldMitm(u64 program_id) {
    if (program_id == OUR_PROGRAM_ID) {
        return false;
    }
    if (!IsApplicationId(program_id)) {
        return false;
    }
    return IsGameInWhitelist(program_id);
}

// ============================================================================
// Tests
// ============================================================================

TEST(system_modules_are_not_applications) {
    ASSERT_FALSE(IsApplicationId(0x0100000000000000ULL));   // SystemProgramId::Start
    ASSERT_FALSE(IsApplicationId(0x010000000000000FULL));   // nifm
    ASSERT_FALSE(IsApplicationId(0x0100000000000012ULL));   // bsdsockets
    ASSERT_FALSE(IsApplicationId(0x010000000000001FULL));   // ns
    ASSERT_FALSE(IsApplicationId(0x01000000000007FFULL));   // SystemProgramId::End
}

TEST(applets_are_not_applications) {
    ASSERT_FALSE(IsApplicationId(0x0100000000001000ULL));   // qlaunch
    ASSERT_FALSE(IsApplicationId(0x010000000000100AULL));   // web applet
    ASSERT_FALSE(IsApplicationId(0x010000000000100DULL));   // photoViewer (hbmenu via album)
}

TEST(own_sysmodule_is_not_an_application) {
    ASSERT_FALSE(IsApplicationId(OUR_PROGRAM_ID));
}

TEST(application_range_bounds) {
    ASSERT_FALSE(IsApplicationId(APPLICATION_ID_START - 1));
    ASSERT_TRUE(IsApplicationId(APPLICATION_ID_START));
    ASSERT_TRUE(IsApplicationId(APPLICATION_ID_END));
    ASSERT_FALSE(IsApplicationId(APPLICATION_ID_END + 1));
}

TEST(whitelisted_games_are_intercepted) {
    ASSERT_TRUE(ShouldMitm(0x0100C2500FC20000ULL));
    ASSERT_TRUE(ShouldMitm(0x0100000011D90000ULL));
}

TEST(non_whitelisted_game_is_not_intercepted) {
    ASSERT_FALSE(ShouldMitm(0x01007EF00011E000ULL));
}

TEST(system_programs_are_not_intercepted) {
    ASSERT_FALSE(ShouldMitm(0x010000000000000FULL));
    ASSERT_FALSE(ShouldMitm(0x0100000000001000ULL));
    ASSERT_FALSE(ShouldMitm(OUR_PROGRAM_ID));
}

// Every shipped whitelist entry must pass the application check, otherwise
// the filter would silently stop intercepting that game.
TEST(shipped_whitelist_is_all_applications) {
    FILE* f = fopen("../config/ryu_ldn_nx/gamelist.txt", "r");
    ASSERT_TRUE(f != nullptr);

    char line[64];
    int count = 0;
    bool all_ok = true;
    while (fgets(line, sizeof(line), f)) {
        u64 id = strtoull(line, nullptr, 16);
        if (id == 0) {
            continue;
        }
        count++;
        if (!IsApplicationId(id)) {
            printf("\n    not an application ID: 0x%016llx", static_cast<unsigned long long>(id));
            all_ok = false;
        }
    }
    fclose(f);

    ASSERT_TRUE(count > 0);
    ASSERT_TRUE(all_ok);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("\n========================================\n");
    printf("  BSD MITM Filter Tests - ryu_ldn_nx\n");
    printf("========================================\n\n");

    // Tests run automatically via static initializers

    printf("\n========================================\n");
    printf("  Results: %d/%d passed\n", g_tests_passed, g_tests_passed + g_tests_failed);
    printf("========================================\n\n");

    return g_tests_failed > 0 ? 1 : 0;
}
