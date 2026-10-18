/**
 * @file config_tests.cpp
 * @brief Unit tests for Configuration Manager
 *
 * Tests for parsing INI config files and default values.
 */

#include "config/config.hpp"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <string>
#include <iterator>

using namespace ryu_ldn::config;

// ============================================================================
// Test Framework (minimal, no external dependencies)
// ============================================================================

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST(name) \
    static void test_##name(); \
    static struct TestRegister_##name { \
        TestRegister_##name() { register_test(#name, test_##name); } \
    } g_test_register_##name; \
    static void test_##name()

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            printf("  FAIL: %s (line %d)\n", #cond, __LINE__); \
            throw std::runtime_error("Test assertion failed"); \
        } \
    } while(0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

#define ASSERT_EQ(a, b) \
    do { \
        auto _a = (a); \
        auto _b = (b); \
        if (_a != _b) { \
            printf("  FAIL: %s == %s (line %d)\n", #a, #b, __LINE__); \
            printf("    got: %lld vs %lld\n", (long long)_a, (long long)_b); \
            throw std::runtime_error("Test assertion failed"); \
        } \
    } while(0)

#define ASSERT_STREQ(a, b) \
    do { \
        const char* _a = (a); \
        const char* _b = (b); \
        if (std::strcmp(_a, _b) != 0) { \
            printf("  FAIL: %s == %s (line %d)\n", #a, #b, __LINE__); \
            printf("    got: \"%s\" vs \"%s\"\n", _a, _b); \
            throw std::runtime_error("Test assertion failed"); \
        } \
    } while(0)

struct TestEntry {
    const char* name;
    void (*func)();
};

static TestEntry g_tests[128];
static int g_test_count = 0;

static void register_test(const char* name, void (*func)()) {
    if (g_test_count < 128) {
        g_tests[g_test_count++] = {name, func};
    }
}

// Helper to create temp config file
class TempConfigFile {
public:
    TempConfigFile(const char* content) {
        snprintf(m_path, sizeof(m_path), "/tmp/test_config_%d.ini", rand());
        std::ofstream f(m_path);
        if (f.is_open()) {
            f << content;
            f.close();
        }
    }

    ~TempConfigFile() {
        std::remove(m_path);
    }

    const char* path() const { return m_path; }

private:
    char m_path[256];
};

// ============================================================================
// Default Values Tests
// ============================================================================

TEST(default_values) {
    Config config = get_default_config();

    // Server defaults: nothing connects until the relay is configured
    ASSERT_STREQ(config.server.host, "");
    ASSERT_EQ(config.server.port, 443);
    ASSERT_TRUE(config.server.transport == Transport::None);
    ASSERT_STREQ(config.server.path, "/ldn");
    ASSERT_STREQ(config.server.console_id, "");
    ASSERT_STREQ(config.server.token, "");
    ASSERT_STREQ(config.server.ca_file, "sdmc:/config/ryu_ldn_nx/ca.pem");

    // LDN defaults
    ASSERT_EQ(config.ldn.enabled, true);
    ASSERT_STREQ(config.ldn.passphrase, "");

    // Debug defaults
    ASSERT_EQ(config.debug.enabled, false);
    ASSERT_EQ(config.debug.level, 1u);

    // LDN passphrase filtering default
    ASSERT_EQ(config.ldn.use_passphrase, false);

    // P2P proxy default (disabled by default)
    ASSERT_EQ(config.ldn.disable_p2p, true);
}

// ============================================================================
// Parse Tests
// ============================================================================

TEST(parse_empty_file) {
    TempConfigFile file("");
    Config config = get_default_config();
    ConfigResult result = load_config(file.path(), config);

    ASSERT_EQ(result, ConfigResult::Success);
    // Should have defaults
    ASSERT_STREQ(config.server.host, DEFAULT_HOST);
}

TEST(parse_server_section) {
    const char* content =
        "[server]\n"
        "host = 192.168.1.100\n"
        "port = 12345\n";

    TempConfigFile file(content);
    Config config = get_default_config();
    ConfigResult result = load_config(file.path(), config);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_STREQ(config.server.host, "192.168.1.100");
    ASSERT_EQ(config.server.port, 12345);
}

TEST(parse_ldn_section) {
    const char* content =
        "[ldn]\n"
        "enabled = 0\n"
        "use_passphrase = 1\n"
        "passphrase = secret123\n"
        "disable_p2p = 0\n";

    TempConfigFile file(content);
    Config config = get_default_config();
    ConfigResult result = load_config(file.path(), config);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_EQ(config.ldn.enabled, false);
    ASSERT_EQ(config.ldn.use_passphrase, true);
    ASSERT_STREQ(config.ldn.passphrase, "secret123");
    ASSERT_EQ(config.ldn.disable_p2p, false);
}

TEST(parse_debug_section) {
    const char* content =
        "[debug]\n"
        "enabled = 1\n"
        "level = 3\n";

    TempConfigFile file(content);
    Config config = get_default_config();
    ConfigResult result = load_config(file.path(), config);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_EQ(config.debug.enabled, true);
    ASSERT_EQ(config.debug.level, 3u);
}

TEST(parse_comments_ignored) {
    const char* content =
        "; This is a comment\n"
        "[server]\n"
        "; Another comment\n"
        "host = test.server.com\n"
        "  ; Indented comment\n"
        "port = 9999\n";

    TempConfigFile file(content);
    Config config = get_default_config();
    ConfigResult result = load_config(file.path(), config);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_STREQ(config.server.host, "test.server.com");
    ASSERT_EQ(config.server.port, 9999);
}

TEST(parse_whitespace_handling) {
    const char* content =
        "[server]\n"
        "  host   =   spaced.server.com  \n"
        "port=12345\n";  // No spaces

    TempConfigFile file(content);
    Config config = get_default_config();
    ConfigResult result = load_config(file.path(), config);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_STREQ(config.server.host, "spaced.server.com");
    ASSERT_EQ(config.server.port, 12345);
}

TEST(parse_unknown_section_ignored) {
    const char* content =
        "[unknown]\n"
        "foo = bar\n"
        "[server]\n"
        "port = 11111\n";

    TempConfigFile file(content);
    Config config = get_default_config();
    ConfigResult result = load_config(file.path(), config);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_EQ(config.server.port, 11111);
}

TEST(parse_unknown_key_ignored) {
    const char* content =
        "[server]\n"
        "unknown_key = value\n"
        "port = 22222\n";

    TempConfigFile file(content);
    Config config = get_default_config();
    ConfigResult result = load_config(file.path(), config);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_EQ(config.server.port, 22222);
}

TEST(file_not_found) {
    Config config = get_default_config();
    ConfigResult result = load_config("/nonexistent/path/config.ini", config);

    ASSERT_EQ(result, ConfigResult::FileNotFound);
    // Config should still have defaults
    ASSERT_STREQ(config.server.host, DEFAULT_HOST);
}

TEST(passphrase_truncated) {
    // Passphrase > 64 chars should be truncated
    const char* content =
        "[ldn]\n"
        "passphrase = 12345678901234567890123456789012345678901234567890123456789012345678901234567890\n";

    TempConfigFile file(content);
    Config config = get_default_config();
    ConfigResult result = load_config(file.path(), config);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_EQ(strlen(config.ldn.passphrase), 64u);
}

TEST(host_truncated) {
    // Host > 128 chars should be truncated
    char long_host[200];
    memset(long_host, 'a', sizeof(long_host) - 1);
    long_host[sizeof(long_host) - 1] = '\0';

    char content[512];
    snprintf(content, sizeof(content), "[server]\nhost = %s\n", long_host);

    TempConfigFile file(content);
    Config config = get_default_config();
    ConfigResult result = load_config(file.path(), config);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_EQ(strlen(config.server.host), 128u);
}

TEST(full_config_example) {
    const char* content =
        "; Full example\n"
        "[server]\n"
        "host = custom.ldn.server\n"
        "port = 30000\n"
        "\n"
        "[ldn]\n"
        "enabled = 1\n"
        "use_passphrase = 0\n"
        "passphrase = myroom\n"
        "disable_p2p = 0\n"
        "\n"
        "[debug]\n"
        "enabled = 1\n"
        "level = 2\n";

    TempConfigFile file(content);
    Config config = get_default_config();
    ConfigResult result = load_config(file.path(), config);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_STREQ(config.server.host, "custom.ldn.server");
    ASSERT_EQ(config.server.port, 30000);
    ASSERT_EQ(config.ldn.enabled, true);
    ASSERT_STREQ(config.ldn.passphrase, "myroom");
    ASSERT_EQ(config.ldn.use_passphrase, false);
    ASSERT_EQ(config.ldn.disable_p2p, false);
    ASSERT_EQ(config.debug.enabled, true);
    ASSERT_EQ(config.debug.level, 2u);
}

// ============================================================================
// Save Config Tests
// ============================================================================

TEST(save_config_creates_file) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/test_save_config_%d.ini", rand());

    Config config = get_default_config();
    ConfigResult result = save_config(path, config);

    ASSERT_EQ(result, ConfigResult::Success);

    // Verify file exists and can be loaded back
    Config loaded = get_default_config();
    loaded.server.port = 0;  // Change to verify it gets loaded
    result = load_config(path, loaded);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_EQ(loaded.server.port, DEFAULT_PORT);

    std::remove(path);
}

TEST(save_config_preserves_values) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/test_save_preserve_%d.ini", rand());

    Config config = get_default_config();
    // Modify some values
    strcpy(config.server.host, "test.example.com");
    config.server.port = 12345;
    config.ldn.enabled = false;
    config.ldn.use_passphrase = true;
    strcpy(config.ldn.passphrase, "testpass");
    config.ldn.disable_p2p = false;
    config.debug.enabled = true;
    config.debug.level = 3;

    ConfigResult result = save_config(path, config);
    ASSERT_EQ(result, ConfigResult::Success);

    // Load it back
    Config loaded = get_default_config();
    result = load_config(path, loaded);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_STREQ(loaded.server.host, "test.example.com");
    ASSERT_EQ(loaded.server.port, 12345);
    ASSERT_EQ(loaded.ldn.enabled, false);
    ASSERT_STREQ(loaded.ldn.passphrase, "testpass");
    ASSERT_EQ(loaded.ldn.use_passphrase, true);
    ASSERT_EQ(loaded.ldn.disable_p2p, false);
    ASSERT_EQ(loaded.debug.enabled, true);
    ASSERT_EQ(loaded.debug.level, 3u);

    std::remove(path);
}

// ============================================================================
// Ensure Config Exists Tests
// ============================================================================

TEST(ensure_config_exists_creates_new) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/test_ensure_%d.ini", rand());

    // Make sure file doesn't exist
    std::remove(path);

    ConfigResult result = ensure_config_exists(path);
    ASSERT_EQ(result, ConfigResult::Success);

    // Verify file was created with defaults
    Config loaded = get_default_config();
    loaded.server.port = 0;  // Change to verify
    result = load_config(path, loaded);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_EQ(loaded.server.port, DEFAULT_PORT);
    ASSERT_STREQ(loaded.server.host, DEFAULT_HOST);

    std::remove(path);
}

TEST(ensure_config_exists_keeps_existing) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/test_ensure_existing_%d.ini", rand());

    // Create a config with custom values
    const char* content =
        "[server]\n"
        "host = custom.host.com\n"
        "port = 54321\n";

    std::ofstream f(path);
    f << content;
    f.close();

    // ensure_config_exists should not overwrite
    ConfigResult result = ensure_config_exists(path);
    ASSERT_EQ(result, ConfigResult::Success);

    // Verify original values are preserved
    Config loaded = get_default_config();
    result = load_config(path, loaded);

    ASSERT_EQ(result, ConfigResult::Success);
    ASSERT_STREQ(loaded.server.host, "custom.host.com");
    ASSERT_EQ(loaded.server.port, 54321);

    std::remove(path);
}

// ============================================================================
// Relay Transport Tests
// ============================================================================

static const char* VALID_TOKEN = "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef";

TEST(parse_relay_keys) {
    char content[512];
    snprintf(content, sizeof(content),
        "[server]\n"
        "host = relay.example.workers.dev\n"
        "transport = wss\n"
        "path = /ldn\n"
        "console_id = switch-1\n"
        "token = %s\n"
        "ca_file = sdmc:/config/ryu_ldn_nx/ca.pem\n", VALID_TOKEN);
    TempConfigFile file(content);
    Config config = get_default_config();
    ASSERT_EQ(load_config(file.path(), config), ConfigResult::Success);

    ASSERT_TRUE(config.server.transport == Transport::Wss);
    ASSERT_STREQ(config.server.console_id, "switch-1");
    // Stored lowercase, as the relay compares it
    ASSERT_STREQ(config.server.token, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
}

TEST(transport_missing_or_unknown_is_none) {
    TempConfigFile empty("[server]\ntransport =\n");
    Config config = get_default_config();
    ASSERT_EQ(load_config(empty.path(), config), ConfigResult::Success);
    ASSERT_TRUE(config.server.transport == Transport::None);

    TempConfigFile tcp("[server]\ntransport = tcp\n");
    config = get_default_config();
    ASSERT_EQ(load_config(tcp.path(), config), ConfigResult::Success);
    ASSERT_TRUE(config.server.transport == Transport::None);
}

TEST(token_rejected_unless_64_hex) {
    const char* bad[] = {
        "0123456789abcdef",                                                    // too short
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",   // too long
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",    // not hex
    };
    for (const char* token : bad) {
        char content[256];
        snprintf(content, sizeof(content), "[server]\ntoken = %s\n", token);
        TempConfigFile file(content);
        Config config = get_default_config();
        ASSERT_EQ(load_config(file.path(), config), ConfigResult::Success);
        ASSERT_STREQ(config.server.token, "");
    }
}

TEST(console_id_rejected_unless_relay_charset) {
    const char* bad[] = {"Switch-1", "switch_1", "0123456789abcdef0123456789abcdef0"};
    for (const char* id : bad) {
        char content[256];
        snprintf(content, sizeof(content), "[server]\nconsole_id = %s\n", id);
        TempConfigFile file(content);
        Config config = get_default_config();
        ASSERT_EQ(load_config(file.path(), config), ConfigResult::Success);
        ASSERT_STREQ(config.server.console_id, "");
    }
}

TEST(wss_transport_forces_p2p_off) {
    TempConfigFile file("[server]\ntransport = wss\n[ldn]\ndisable_p2p = 0\n");
    Config config = get_default_config();
    ASSERT_EQ(load_config(file.path(), config), ConfigResult::Success);
    ASSERT_EQ(config.ldn.disable_p2p, true);
}

TEST(save_config_keeps_relay_keys) {
    char content[512];
    snprintf(content, sizeof(content),
        "[server]\nhost = relay.example\ntransport = wss\nconsole_id = switch-1\ntoken = %s\n", VALID_TOKEN);
    TempConfigFile file(content);
    Config config = get_default_config();
    ASSERT_EQ(load_config(file.path(), config), ConfigResult::Success);

    char path[256];
    snprintf(path, sizeof(path), "/tmp/test_save_relay_%d.ini", rand());
    ASSERT_EQ(save_config(path, config), ConfigResult::Success);
    Config loaded = get_default_config();
    ASSERT_EQ(load_config(path, loaded), ConfigResult::Success);
    std::remove(path);

    ASSERT_TRUE(loaded.server.transport == Transport::Wss);
    ASSERT_STREQ(loaded.server.console_id, "switch-1");
    ASSERT_STREQ(loaded.server.token, config.server.token);
    ASSERT_EQ(loaded.server.port, config.server.port);
}

static std::string read_all(const char* path) {
    std::ifstream f(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

// The file written by save_config must contain every key, including port.
// (Regression: the Switch formatter used to drop `port`; now host tests run
// that same formatter.)
TEST(save_config_writes_port_and_relay_keys) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/test_save_port_%d.ini", rand());
    Config config = get_default_config();
    config.server.port = 4443;
    ASSERT_EQ(save_config(path, config), ConfigResult::Success);
    std::string text = read_all(path);
    std::remove(path);
    ASSERT_TRUE(text.find("port = 4443\n") != std::string::npos);
    ASSERT_TRUE(text.find("transport = ") != std::string::npos);
    ASSERT_TRUE(text.find("path = ") != std::string::npos);
    ASSERT_TRUE(text.find("console_id = ") != std::string::npos);
    ASSERT_TRUE(text.find("token = ") != std::string::npos);
    ASSERT_TRUE(text.find("ca_file = ") != std::string::npos);
}

// Every config save must write the token back unchanged, repeatedly.
TEST(save_config_token_round_trip_is_stable) {
    char content[512];
    snprintf(content, sizeof(content),
        "[server]\nhost = relay.example\ntransport = wss\nconsole_id = switch-1\ntoken = %s\n", VALID_TOKEN);
    TempConfigFile file(content);
    Config config = get_default_config();
    ASSERT_EQ(load_config(file.path(), config), ConfigResult::Success);

    char path[256];
    snprintf(path, sizeof(path), "/tmp/test_token_rt_%d.ini", rand());
    ASSERT_EQ(save_config(path, config), ConfigResult::Success);
    std::string first = read_all(path);
    for (int i = 0; i < 3; i++) {
        Config again = get_default_config();
        ASSERT_EQ(load_config(path, again), ConfigResult::Success);
        ASSERT_STREQ(again.server.token, config.server.token);
        ASSERT_EQ(save_config(path, again), ConfigResult::Success);
    }
    std::string last = read_all(path);
    std::remove(path);
    ASSERT_TRUE(first == last);
    ASSERT_TRUE(last.find(std::string("token = ") + config.server.token + "\n") != std::string::npos);
}

// Overwriting an existing file works (the test io_rename refuses to replace,
// like Horizon fs) and leaves no .tmp behind.
TEST(save_config_overwrites_existing_without_tmp) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/test_save_atomic_%d.ini", rand());
    Config config = get_default_config();
    ASSERT_EQ(save_config(path, config), ConfigResult::Success);
    config.server.port = 1111;
    ASSERT_EQ(save_config(path, config), ConfigResult::Success);

    Config loaded = get_default_config();
    ASSERT_EQ(load_config(path, loaded), ConfigResult::Success);
    ASSERT_EQ(loaded.server.port, 1111);

    char tmp[272];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    std::ifstream t(tmp);
    ASSERT_FALSE(t.good());
    std::remove(path);
}

// Crash between "delete config.ini" and "rename tmp": boot must recover.
TEST(ensure_config_exists_recovers_tmp) {
    char path[256], tmp[272];
    snprintf(path, sizeof(path), "/tmp/test_recover_%d.ini", rand());
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    std::remove(path);
    { std::ofstream f(tmp); f << "[server]\nhost = recovered.example\nport = 777\n"; }

    ASSERT_EQ(ensure_config_exists(path), ConfigResult::Success);
    Config loaded = get_default_config();
    ASSERT_EQ(load_config(path, loaded), ConfigResult::Success);
    std::remove(path);
    ASSERT_STREQ(loaded.server.host, "recovered.example");
    ASSERT_EQ(loaded.server.port, 777);
    std::ifstream t(tmp);
    ASSERT_FALSE(t.good());
}

// A stale .tmp next to a valid config.ini must never win.
TEST(ensure_config_exists_ignores_tmp_when_config_present) {
    char path[256], tmp[272];
    snprintf(path, sizeof(path), "/tmp/test_ignoretmp_%d.ini", rand());
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    { std::ofstream f(path); f << "[server]\nport = 1\n"; }
    { std::ofstream f(tmp); f << "[server]\nport = 2\n"; }
    ASSERT_EQ(ensure_config_exists(path), ConfigResult::Success);
    Config loaded = get_default_config();
    ASSERT_EQ(load_config(path, loaded), ConfigResult::Success);
    std::remove(path);
    std::remove(tmp);
    ASSERT_EQ(loaded.server.port, 1);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("=== ryu_ldn_nx Config Unit Tests ===\n\n");
    printf("Running %d tests...\n\n", g_test_count);

    for (int i = 0; i < g_test_count; i++) {
        g_tests_run++;
        printf("[%d/%d] %s...", i + 1, g_test_count, g_tests[i].name);
        fflush(stdout);

        try {
            g_tests[i].func();
            printf(" OK\n");
            g_tests_passed++;
        } catch (...) {
            g_tests_failed++;
        }
    }

    printf("\n========================================\n");
    printf("Results: %d passed, %d failed, %d total\n",
           g_tests_passed, g_tests_failed, g_tests_run);

    if (g_tests_failed == 0) {
        printf("ALL TESTS PASSED\n");
    } else {
        printf("FAILED\n");
    }

    return g_tests_failed > 0 ? 1 : 0;
}
