/**
 * @file config.cpp
 * @brief Configuration Manager Implementation
 *
 * On Nintendo Switch (Atmosphere), uses ams::fs API for safe SD card access
 * at boot. The standard library fopen/fclose causes kernel panic (DABRT 0x101)
 * when called before the filesystem is fully ready.
 *
 * For testing on PC, uses standard C file I/O.
 */

#include "config.hpp"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <new>

#ifdef __SWITCH__
#include <stratosphere.hpp>
#else
#include <sys/stat.h>
#endif

namespace ryu_ldn::config {

// ============================================================================
// Helper Functions
// ============================================================================

namespace {

/**
 * @brief Trim leading whitespace from string
 */
const char* trim_start(const char* str) {
    while (*str == ' ' || *str == '\t') {
        str++;
    }
    return str;
}

/**
 * @brief Trim trailing whitespace from string (modifies in place)
 */
void trim_end(char* str) {
    size_t len = std::strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\t' ||
                       str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[--len] = '\0';
    }
}

/**
 * @brief Copy string with length limit
 */
void safe_strcpy(char* dest, const char* src, size_t max_len) {
    size_t i = 0;
    while (i < max_len && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

/**
 * @brief Parse boolean value (0/1, true/false, yes/no)
 */
bool parse_bool(const char* value) {
    if (value[0] == '0' || value[0] == 'f' || value[0] == 'F' ||
        value[0] == 'n' || value[0] == 'N') {
        return false;
    }
    return true;  // Default to true for any non-false value
}

/**
 * @brief Parse unsigned integer
 */
uint32_t parse_uint32(const char* value) {
    return static_cast<uint32_t>(std::strtoul(value, nullptr, 10));
}

/**
 * @brief Parse unsigned 16-bit integer
 */
uint16_t parse_uint16(const char* value) {
    return static_cast<uint16_t>(std::strtoul(value, nullptr, 10));
}

/**
 * @brief Store the relay token if it is exactly 64 hex characters
 *
 * The token is normalised to lowercase (the relay hashes the exact string).
 * Anything else leaves the token empty so the client refuses to connect.
 */
void parse_token(const char* value, char* token) {
    token[0] = '\0';
    if (std::strlen(value) != TOKEN_LENGTH) {
        return;
    }
    for (size_t i = 0; i < TOKEN_LENGTH; i++) {
        char c = value[i];
        if (c >= 'A' && c <= 'F') {
            c = static_cast<char>(c - 'A' + 'a');
        }
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            token[0] = '\0';
            return;
        }
        token[i] = c;
    }
    token[TOKEN_LENGTH] = '\0';
}

/**
 * @brief Store the console ID if it matches the relay's [a-z0-9-]{1,32} rule
 */
void parse_console_id(const char* value, char* console_id) {
    console_id[0] = '\0';
    size_t len = std::strlen(value);
    if (len == 0 || len > MAX_CONSOLE_ID_LENGTH) {
        return;
    }
    for (size_t i = 0; i < len; i++) {
        char c = value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
            return;
        }
    }
    safe_strcpy(console_id, value, MAX_CONSOLE_ID_LENGTH);
}

/**
 * @brief Enforce cross-section rules after a load
 *
 * P2P opens sockets outside the TLS-protected relay path, so it is
 * forced off whenever the secure transport is selected.
 */
void apply_constraints(Config& config) {
    if (config.server.transport == Transport::Wss) {
        config.ldn.disable_p2p = true;
    }
}

// Section identifiers
enum class Section {
    None,
    Server,
    Ldn,
    Debug,
    Unknown
};

/**
 * @brief Identify section from header line
 */
Section parse_section(const char* line) {
    if (std::strcmp(line, "[server]") == 0) return Section::Server;
    if (std::strcmp(line, "[ldn]") == 0) return Section::Ldn;
    if (std::strcmp(line, "[debug]") == 0) return Section::Debug;
    if (line[0] == '[') return Section::Unknown;
    return Section::None;
}

/**
 * @brief Process a key=value line for server section
 */
void process_server_key(const char* key, const char* value, ServerConfig& config) {
    if (std::strcmp(key, "host") == 0) {
        safe_strcpy(config.host, value, MAX_HOST_LENGTH);
    } else if (std::strcmp(key, "port") == 0) {
        config.port = parse_uint16(value);
    } else if (std::strcmp(key, "transport") == 0) {
        config.transport = std::strcmp(value, "wss") == 0 ? Transport::Wss : Transport::None;
    } else if (std::strcmp(key, "path") == 0) {
        safe_strcpy(config.path, value, MAX_PATH_LENGTH);
    } else if (std::strcmp(key, "console_id") == 0) {
        parse_console_id(value, config.console_id);
    } else if (std::strcmp(key, "token") == 0) {
        parse_token(value, config.token);
    } else if (std::strcmp(key, "ca_file") == 0) {
        safe_strcpy(config.ca_file, value, MAX_CA_FILE_LENGTH);
    }
}

/**
 * @brief Process a key=value line for ldn section
 */
void process_ldn_key(const char* key, const char* value, LdnConfig& config) {
    if (std::strcmp(key, "enabled") == 0) {
        config.enabled = parse_bool(value);
    } else if (std::strcmp(key, "passphrase") == 0) {
        safe_strcpy(config.passphrase, value, MAX_PASSPHRASE_LENGTH);
    } else if (std::strcmp(key, "use_passphrase") == 0) {
        config.use_passphrase = parse_bool(value);
    } else if (std::strcmp(key, "disable_p2p") == 0) {
        config.disable_p2p = parse_bool(value);
    }
}

/**
 * @brief Process a key=value line for debug section
 */
void process_debug_key(const char* key, const char* value, DebugConfig& config) {
    if (std::strcmp(key, "enabled") == 0) {
        config.enabled = parse_bool(value);
    } else if (std::strcmp(key, "level") == 0) {
        config.level = parse_uint32(value);
    }
}

/**
 * @brief Parse file content line by line (for ams::fs buffer-based reading)
 */
/// @gdb{tag="CONFIG:PARSE", msg="Parsing config content"}
void parse_config_content(const char* content, size_t size, Config& config) {
    char line[512];
    Section current_section = Section::None;
    size_t line_pos = 0;

    size_t i = 0;
    while (i <= size) {
        // End of line or end of content
        if (i == size || content[i] == '\n' || content[i] == '\r') {
            line[line_pos] = '\0';

            if (line_pos > 0) {
                // Remove trailing whitespace/newlines
                trim_end(line);

                // Skip empty lines
                const char* trimmed = trim_start(line);
                if (trimmed[0] != '\0') {
                    // Skip comments
                    if (trimmed[0] != ';' && trimmed[0] != '#') {
                        // Check for section header
                        Section new_section = parse_section(trimmed);
                        if (new_section != Section::None) {
                            current_section = new_section;
                        } else if (current_section != Section::None &&
                                   current_section != Section::Unknown) {
                            // Parse key=value
                            char* eq_pos = std::strchr(line, '=');
                            if (eq_pos) {
                                *eq_pos = '\0';
                                char* key = line;
                                char* value = eq_pos + 1;

                                // Trim key and value
                                const char* trimmed_key = trim_start(key);
                                trim_end(key);

                                const char* trimmed_value = trim_start(value);
                                trim_end(value);

                                // Copy trimmed key
                                char key_buf[64];
                                safe_strcpy(key_buf, trimmed_key, sizeof(key_buf) - 1);
                                trim_end(key_buf);

                                // Process based on current section
                                switch (current_section) {
                                    case Section::Server:
                                        process_server_key(key_buf, trimmed_value, config.server);
                                        break;
                                    case Section::Ldn:
                                        process_ldn_key(key_buf, trimmed_value, config.ldn);
                                        break;
                                    case Section::Debug:
                                        process_debug_key(key_buf, trimmed_value, config.debug);
                                        break;
                                    default:
                                        break;
                                }
                            }
                        }
                    }
                }
            }

            line_pos = 0;
            // Skip \r if followed by \n
            if (i < size && content[i] == '\r' && i + 1 < size && content[i + 1] == '\n') {
                i++;
            }
        } else if (line_pos < sizeof(line) - 1) {
            line[line_pos++] = content[i];
        }
        i++;
    }
}

/**
 * @brief Format config content into buffer for writing
 * @return Number of bytes written, or 0 if the buffer was too small
 */
size_t format_config_content(char* buffer, size_t buffer_size, const Config& config) {
    size_t offset = 0;
    bool overflow = false;

    #define WRITE_LINE(fmt, ...) do { \
        int written = std::snprintf(buffer + offset, buffer_size - offset, fmt "\n", ##__VA_ARGS__); \
        if (written > 0 && offset + written < buffer_size) offset += written; \
        else overflow = true; \
    } while(0)

    WRITE_LINE("; ryu_ldn_nx Configuration");
    WRITE_LINE("; Auto-generated on first boot");
    WRITE_LINE("; Edit this file to customize settings");
    WRITE_LINE("");

    WRITE_LINE("[server]");
    WRITE_LINE("; Relay hostname (empty = do not connect)");
    WRITE_LINE("host = %s", config.server.host);
    WRITE_LINE("; Server port");
    WRITE_LINE("port = %u", config.server.port);
    WRITE_LINE("; Secure WebSocket transport (plain TCP is refused)");
    WRITE_LINE("transport = %s", config.server.transport == Transport::Wss ? "wss" : "");
    WRITE_LINE("path = %s", config.server.path);
    WRITE_LINE("console_id = %s", config.server.console_id);
    WRITE_LINE("; Secret: 64 hex characters, one per console");
    WRITE_LINE("token = %s", config.server.token);
    WRITE_LINE("ca_file = %s", config.server.ca_file);
    WRITE_LINE("");

    WRITE_LINE("[ldn]");
    WRITE_LINE("; Enable LDN emulation (0/1)");
    WRITE_LINE("enabled = %d", config.ldn.enabled ? 1 : 0);
    WRITE_LINE("; Enable passphrase filtering (0/1)");
    WRITE_LINE("use_passphrase = %d", config.ldn.use_passphrase ? 1 : 0);
    WRITE_LINE("; Room passphrase (empty = public)");
    WRITE_LINE("passphrase = %s", config.ldn.passphrase);
    WRITE_LINE("; Disable P2P proxy (0/1) - like Ryujinx MultiplayerDisableP2p");
    WRITE_LINE("disable_p2p = %d", config.ldn.disable_p2p ? 1 : 0);
    WRITE_LINE("");

    WRITE_LINE("[debug]");
    WRITE_LINE("; Enable debug logging (0/1)");
    WRITE_LINE("enabled = %d", config.debug.enabled ? 1 : 0);
    WRITE_LINE("; Log level (0=errors, 1=warnings, 2=info, 3=verbose)");
    WRITE_LINE("level = %u", config.debug.level);

    #undef WRITE_LINE

    return overflow ? 0 : offset;  // 0 = truncated, caller must not save
}

} // anonymous namespace

// ============================================================================
// Public Functions
// ============================================================================

Config get_default_config() {
    Config config{};

    // Server defaults
    safe_strcpy(config.server.host, DEFAULT_HOST, MAX_HOST_LENGTH);
    config.server.port = DEFAULT_PORT;
    config.server.transport = DEFAULT_TRANSPORT;
    safe_strcpy(config.server.path, DEFAULT_PATH, MAX_PATH_LENGTH);
    config.server.console_id[0] = '\0';
    config.server.token[0] = '\0';
    safe_strcpy(config.server.ca_file, DEFAULT_CA_FILE, MAX_CA_FILE_LENGTH);

    // LDN defaults
    config.ldn.enabled = DEFAULT_LDN_ENABLED;
    config.ldn.passphrase[0] = '\0';
    config.ldn.use_passphrase = DEFAULT_USE_PASSPHRASE;
    config.ldn.disable_p2p = DEFAULT_DISABLE_P2P;

    // Debug defaults
    config.debug.enabled = DEFAULT_DEBUG_ENABLED;
    config.debug.level = DEFAULT_DEBUG_LEVEL;

    return config;
}


// =============================================================================
// File I/O primitives (the only platform-specific part)
//
// load/save/ensure below are shared, so host tests run the exact parser and
// formatter the Switch build uses.
// =============================================================================

namespace {

constexpr size_t MAX_CONFIG_FILE_SIZE = 65536;
constexpr size_t FORMAT_BUFFER_SIZE = 4096;

bool make_tmp_path(const char* path, char* tmp, size_t tmp_size) {
    size_t len = std::strlen(path);
    if (len + 5 > tmp_size) return false;  // ".tmp" + NUL
    std::memcpy(tmp, path, len);
    std::memcpy(tmp + len, ".tmp", 5);
    return true;
}

#ifdef __SWITCH__

bool io_exists(const char* path) {
    ams::fs::DirectoryEntryType type;
    return R_SUCCEEDED(ams::fs::GetEntryType(&type, path)) &&
           type == ams::fs::DirectoryEntryType_File;
}

void io_make_parent_dir(const char* path) {
    char dir_path[256];
    safe_strcpy(dir_path, path, sizeof(dir_path) - 1);
    char* last_slash = std::strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        ams::fs::EnsureDirectory(dir_path);
    }
}

void io_delete(const char* path) {
    if (io_exists(path)) ams::fs::DeleteFile(path);
}

bool io_rename(const char* from, const char* to) {
    return R_SUCCEEDED(ams::fs::RenameFile(from, to));
}

/// Create + write + flush + close. Caller deletes any stale file first.
bool io_write(const char* path, const char* data, size_t size) {
    if (R_FAILED(ams::fs::CreateFile(path, static_cast<s64>(size)))) return false;
    ams::fs::FileHandle file;
    if (R_FAILED(ams::fs::OpenFile(&file, path, ams::fs::OpenMode_Write))) return false;
    ams::Result rc = ams::fs::WriteFile(file, 0, data, size, ams::fs::WriteOption::Flush);
    ams::fs::CloseFile(file);
    return R_SUCCEEDED(rc);
}

/// Returns a new[] buffer (caller frees) or nullptr; sets result on failure.
char* io_read(const char* path, size_t& size, ConfigResult& result) {
    if (!io_exists(path)) { result = ConfigResult::FileNotFound; return nullptr; }
    ams::fs::FileHandle file;
    if (R_FAILED(ams::fs::OpenFile(&file, path, ams::fs::OpenMode_Read))) {
        result = ConfigResult::IoError; return nullptr;
    }
    s64 file_size;
    if (R_FAILED(ams::fs::GetFileSize(&file_size, file))) {
        ams::fs::CloseFile(file); result = ConfigResult::IoError; return nullptr;
    }
    if (file_size <= 0 || file_size > static_cast<s64>(MAX_CONFIG_FILE_SIZE)) {
        ams::fs::CloseFile(file);
        result = file_size == 0 ? ConfigResult::FileNotFound : ConfigResult::ParseError;
        return nullptr;
    }
    char* content = new (std::nothrow) char[file_size + 1];
    if (!content) { ams::fs::CloseFile(file); result = ConfigResult::IoError; return nullptr; }
    ams::Result rc = ams::fs::ReadFile(&size, file, 0, content, static_cast<size_t>(file_size));
    ams::fs::CloseFile(file);
    if (R_FAILED(rc)) { delete[] content; result = ConfigResult::IoError; return nullptr; }
    content[size] = '\0';
    return content;
}

#else  // host

bool io_exists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

void io_make_parent_dir(const char* path) {
    char dir_path[256];
    safe_strcpy(dir_path, path, sizeof(dir_path) - 1);
    char* last_slash = std::strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(dir_path, 0755);
    }
}

void io_delete(const char* path) { std::remove(path); }

bool io_rename(const char* from, const char* to) {
    // Like Horizon fs, refuse to replace an existing destination so tests
    // catch a save path that forgets to delete first.
    if (io_exists(to)) return false;
    return std::rename(from, to) == 0;
}

bool io_write(const char* path, const char* data, size_t size) {
    // The Switch SD card uses FAT32/exFAT which has no POSIX permission
    // model; chmod is a no-op there.  // codeql[cpp/world-writable-file-creation]
    FILE* file = std::fopen(path, "wb");
    if (!file) return false;
    bool ok = std::fwrite(data, 1, size, file) == size;
    ok = (std::fflush(file) == 0) && ok;
    ok = (std::fclose(file) == 0) && ok;
    return ok;
}

char* io_read(const char* path, size_t& size, ConfigResult& result) {
    FILE* file = std::fopen(path, "rb");
    if (!file) { result = ConfigResult::FileNotFound; return nullptr; }
    char* content = new (std::nothrow) char[MAX_CONFIG_FILE_SIZE + 1];
    if (!content) { std::fclose(file); result = ConfigResult::IoError; return nullptr; }
    size = std::fread(content, 1, MAX_CONFIG_FILE_SIZE, file);
    std::fclose(file);
    content[size] = '\0';
    return content;
}

#endif

/// Finish an interrupted save: config.ini deleted, config.ini.tmp complete.
bool recover_tmp(const char* path) {
    char tmp[272];
    if (io_exists(path) || !make_tmp_path(path, tmp, sizeof(tmp)) || !io_exists(tmp)) {
        return false;
    }
    return io_rename(tmp, path);
}

} // anonymous namespace

ConfigResult load_config(const char* path, Config& config) {
    size_t size = 0;
    ConfigResult result = ConfigResult::Success;
    char* content = io_read(path, size, result);
    if (!content && result == ConfigResult::FileNotFound && recover_tmp(path)) {
        content = io_read(path, size, result);
    }
    if (!content) return result;

    parse_config_content(content, size, config);
    apply_constraints(config);

    std::memset(content, 0, size);  // the buffer held the relay token
    delete[] content;
    return ConfigResult::Success;
}

ConfigResult save_config(const char* path, const Config& config) {
    char tmp[272];
    if (!make_tmp_path(path, tmp, sizeof(tmp))) return ConfigResult::IoError;

    io_make_parent_dir(path);

    char* buffer = new (std::nothrow) char[FORMAT_BUFFER_SIZE];
    if (!buffer) return ConfigResult::IoError;
    size_t size = format_config_content(buffer, FORMAT_BUFFER_SIZE, config);

    // Horizon fs cannot rename onto an existing file, so: write the complete
    // tmp first, then delete the old file, then rename. A crash after the
    // delete leaves a complete tmp that ensure/load_config renames in.
    io_delete(tmp);
    bool ok = size > 0 && io_write(tmp, buffer, size);
    std::memset(buffer, 0, FORMAT_BUFFER_SIZE);  // held the relay token
    delete[] buffer;

    if (!ok) {
        io_delete(tmp);
        return ConfigResult::IoError;
    }
    io_delete(path);
    return io_rename(tmp, path) ? ConfigResult::Success : ConfigResult::IoError;
}

ConfigResult ensure_config_exists(const char* path) {
    if (io_exists(path) || recover_tmp(path)) {
        return ConfigResult::Success;
    }
    Config default_config = get_default_config();
    return save_config(path, default_config);
}

} // namespace ryu_ldn::config
