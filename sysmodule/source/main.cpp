/**
 * @file main.cpp
 * @brief ryu_ldn_nx - Nintendo Switch LDN to Ryujinx Server Bridge
 *
 * This sysmodule enables Nintendo Switch games to use the Ryujinx LDN
 * servers for online multiplayer, replacing the need for local wireless
 * or complex LAN play setups.
 *
 * Built on Atmosphere's libstratosphere framework.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include <stratosphere.hpp>
#include <atomic>

extern "C" {
#include <switch/services/bsd.h>
}

#include "ldn/ldn_mitm_service.hpp"
#include "bsd/bsd_mitm_service.hpp"
#include "config/config.hpp"
#include "config/config_ipc_service.hpp"
#include "config/game_whitelist.hpp"
#include "debug/log.hpp"
#include "ldn/ldn_shared_state.hpp"

namespace ams {

    namespace {

        // ====================================================================
        // Memory Configuration
        // ====================================================================

        /// Main malloc buffer size
        /// NOTE: Switch sysmodules share ~10MB total, keep this small!
        /// 1 MB is sufficient for TlsHeapCentral and gameplay traffic
        constexpr size_t MallocBufferSize = 1_MB;
        alignas(os::MemoryPageSize) constinit u8 g_malloc_buffer[MallocBufferSize];

        /// Socket buffer configuration
        // codeql[cpp/unused-static-function] — consteval, used at compile-time below
        consteval size_t GetLibnxBsdTransferMemorySize(const ::SocketInitConfig* config) {
            const u32 tcp_tx_buf_max_size = config->tcp_tx_buf_max_size != 0
                ? config->tcp_tx_buf_max_size : config->tcp_tx_buf_size;
            const u32 tcp_rx_buf_max_size = config->tcp_rx_buf_max_size != 0
                ? config->tcp_rx_buf_max_size : config->tcp_rx_buf_size;
            const u32 sum = tcp_tx_buf_max_size + tcp_rx_buf_max_size +
                            config->udp_tx_buf_size + config->udp_rx_buf_size;

            return static_cast<size_t>(config->sb_efficiency) * util::AlignUp(sum, os::MemoryPageSize);
        }

        /// Socket initialization configuration
        constexpr const ::SocketInitConfig LibnxSocketInitConfig = {
            .tcp_tx_buf_size     = 0x800,
            .tcp_rx_buf_size     = 0x1000,
            .tcp_tx_buf_max_size = 0x2000,
            .tcp_rx_buf_max_size = 0x2000,
            .udp_tx_buf_size     = 0x2000,
            .udp_rx_buf_size     = 0x2000,
            .sb_efficiency       = 4,
            // num_bsd_sessions = number of IPC sessions to bsd:s — i.e. the
            // max concurrency for blocking BSD calls. Each blocked recv()/
            // accept()/send() holds one session for the entire IPC round-trip.
            //
            // Worst-case host-side concurrency in P2P mode (LDN = 8 players
            // total = host + 7 joiners):
            //   - master TCP recv          : 1
            //   - P2pProxyServer accept    : 1
            //   - P2pProxyClient (loopback) recv : 1
            //   - 8 P2pProxySession recv   (1 loopback + 7 joiners)
            //   = 11 blocking calls + marge for setsockopt/bind/send.
            //
            // The default of 3 saturated as soon as the loopback session was
            // alive (master recv + accept + 2 loopback recvs = 4 already > 3),
            // and bsd:s on Switch returns errno=113 (EHOSTUNREACH-mapped
            // "no resources") on the 4th concurrent call instead of blocking
            // — which is what made the AcceptLoop spin endlessly.
            //
            // 14 is ConcurrencyLimitMax in libstratosphere
            // (socket_constants.hpp:35), the highest value the kernel will
            // accept; transfer-memory size is independent of this count, so
            // headroom is free.
            .num_bsd_sessions    = 14,
            // bsd:s (System) is required for privileged socket options like
            // IP_MULTICAST_TTL / IP_MULTICAST_IF / IP_ADD_MEMBERSHIP that
            // miniupnpc's upnpDiscover() relies on. bsd:u returned EPERM and
            // miniupnpc crashed instead of handling the error gracefully.
            .bsd_service_type    = BsdServiceType_System,
        };

        /// Socket transfer memory buffer
        alignas(os::MemoryPageSize) constinit u8 g_socket_tmem_buffer[
            GetLibnxBsdTransferMemorySize(std::addressof(LibnxSocketInitConfig))];

        /// BSD initialization configuration
        constexpr const ::BsdInitConfig LibnxBsdInitConfig = {
            .version             = 1,
            .tmem_buffer         = g_socket_tmem_buffer,
            .tmem_buffer_size    = sizeof(g_socket_tmem_buffer),
            .tcp_tx_buf_size     = LibnxSocketInitConfig.tcp_tx_buf_size,
            .tcp_rx_buf_size     = LibnxSocketInitConfig.tcp_rx_buf_size,
            .tcp_tx_buf_max_size = LibnxSocketInitConfig.tcp_tx_buf_max_size,
            .tcp_rx_buf_max_size = LibnxSocketInitConfig.tcp_rx_buf_max_size,
            .udp_tx_buf_size     = LibnxSocketInitConfig.udp_tx_buf_size,
            .udp_rx_buf_size     = LibnxSocketInitConfig.udp_rx_buf_size,
            .sb_efficiency       = LibnxSocketInitConfig.sb_efficiency,
        };

    }

    // ========================================================================
    // MITM Server Configuration
    // ========================================================================

    namespace mitm {

        /// Thread priority for the MITM service
        const s32 ThreadPriority = 6;

        /// ldn:u server threads (main thread + extra)
        const size_t TotalThreads = 2;
        const size_t NumExtraThreads = TotalThreads - 1;

        /// Thread stack size
        // 32 KB: needed because miniupnpc's upnpDiscover() and minissdpc helpers
        // each allocate ~2 KB of stack frames; cumulative with IPC dispatch +
        // ICommunicationService::CreateNetwork → NatPunch → Discover, 16 KB
        // overflowed and DABRT'd on the very first call into upnpDiscover.
        const size_t ThreadStackSize = 0x8000;

        /// Thread stack
        alignas(os::MemoryPageSize) u8 g_thread_stack[ThreadStackSize];
        os::ThreadType g_thread;

        /// bsd:u server threads. bsd:u has its own pool so a game parking
        /// threads in blocking socket calls can never starve ldn:u (and the
        /// session close that would unblock it). Deepest measured bsd path is
        /// the proxy send chain into RyuLdnClient (see BsdThreadStackSize).
        const size_t BsdThreadCount = 3;
        const size_t BsdThreadStackSize = 0x4000;
        alignas(os::MemoryPageSize) u8 g_bsd_thread_stacks[BsdThreadCount][BsdThreadStackSize];
        os::ThreadType g_bsd_threads[BsdThreadCount];

        // Heap for dynamic allocations
        // NOTE: 384KB covers: game whitelist (~40KB), proxy sockets (~16.5KB each,
        // at most MAX_PROXY_SOCKETS = 8), ExpHeap overhead/fragmentation, and
        // transient std::vector/std::deque allocations. 96KB saturated under real gameplay traffic and caused DABRT
        // 0x101 on allocation failure.
        alignas(0x40) constinit u8 g_heap_memory[384_KB];
        constinit lmem::HeapHandle g_heap_handle;
        constinit std::atomic<bool> g_heap_initialized{false};
        constinit os::SdkMutex g_heap_init_mutex;

        lmem::HeapHandle GetHeapHandle() {
            // Acquire pairs with the release below, so a thread that sees
            // true also sees g_heap_handle
            if (AMS_UNLIKELY(!g_heap_initialized.load(std::memory_order_acquire))) {
                std::scoped_lock lk(g_heap_init_mutex);

                if (AMS_LIKELY(!g_heap_initialized.load(std::memory_order_relaxed))) {
                    g_heap_handle = lmem::CreateExpHeap(g_heap_memory, sizeof(g_heap_memory),
                                                        lmem::CreateOption_ThreadSafe);
                    g_heap_initialized.store(true, std::memory_order_release);
                }
            }

            return g_heap_handle;
        }

        void* Allocate(size_t size) {
            return lmem::AllocateFromExpHeap(GetHeapHandle(), size);
        }

        void Deallocate(void* p, size_t size) {
            AMS_UNUSED(size);
            return lmem::FreeToExpHeap(GetHeapHandle(), p);
        }

        namespace {

            /// Server manager options
            struct LdnMitmManagerOptions {
                static constexpr size_t PointerBufferSize   = 0x1000;
                static constexpr size_t MaxDomains          = 0x10;
                static constexpr size_t MaxDomainObjects    = 0x100;
                static constexpr bool   CanDeferInvokeRequest = false;
                static constexpr bool   CanManageMitmServers  = true;
            };

            /// Maximum concurrent sessions per service. A game holds about
            /// three ldn:u sessions (service, communication object, process
            /// monitor) and several bsd:u sessions (one per pooled client).
            constexpr size_t LdnMaxSessions = 6;
            constexpr size_t BsdMaxSessions = 14;

            /// One single-port MITM server manager per service, so each
            /// service gets its own threads.
            template<typename Interface, typename Impl, size_t MaxSessions>
            class MitmServerManager final : public sf::hipc::ServerManager<1, LdnMitmManagerOptions, MaxSessions> {
            private:
                using Base = sf::hipc::ServerManager<1, LdnMitmManagerOptions, MaxSessions>;

                virtual ams::Result OnNeedsToAccept(int port_index, typename Base::Server* server) override {
                    AMS_UNUSED(port_index);

                    std::shared_ptr<::Service> fsrv;
                    sm::MitmProcessInfo client_info;
                    server->AcknowledgeMitmSession(std::addressof(fsrv), std::addressof(client_info));

                    LOG_INFO("OnNeedsToAccept: pid=%lu, program_id=0x%016lx, fsrv handle=0x%x",
                             client_info.process_id.value, client_info.program_id.value, fsrv ? fsrv->session : 0);

                    R_RETURN(this->AcceptMitmImpl(
                        server, sf::CreateSharedObjectEmplaced<Interface, Impl>(decltype(fsrv)(fsrv), client_info), fsrv));
                }
            };

            MitmServerManager<mitm::ldn::ILdnMitMService, mitm::ldn::LdnMitMService, LdnMaxSessions> g_server_manager;
            MitmServerManager<mitm::bsd::IBsdMitmService, mitm::bsd::BsdMitmService, BsdMaxSessions> g_bsd_server_manager;

            void LoopBsdServerThread(void*) {
                g_bsd_server_manager.LoopProcess();
            }

            // Extra threads for parallel request handling
            alignas(os::MemoryPageSize) u8 g_extra_thread_stacks[NumExtraThreads][ThreadStackSize];
            os::ThreadType g_extra_threads[NumExtraThreads];

            void LoopServerThread(void*) {
                g_server_manager.LoopProcess();
            }

            void ProcessForServerOnAllThreads(void*) {
                // Initialize extra threads
                if constexpr (NumExtraThreads > 0) {
                    const s32 priority = os::GetThreadCurrentPriority(os::GetCurrentThread());
                    for (size_t i = 0; i < NumExtraThreads; i++) {
                        R_ABORT_UNLESS(os::CreateThread(g_extra_threads + i, LoopServerThread,
                                                         nullptr, g_extra_thread_stacks[i],
                                                         ThreadStackSize, priority));
                        os::SetThreadNamePointer(g_extra_threads + i, "ryu_ldn::Thread");
                    }
                }

                // Start extra threads
                if constexpr (NumExtraThreads > 0) {
                    for (size_t i = 0; i < NumExtraThreads; i++) {
                        os::StartThread(g_extra_threads + i);
                    }
                }

                // Loop this thread
                LoopServerThread(nullptr);

                // Wait for extra threads to finish
                if constexpr (NumExtraThreads > 0) {
                    for (size_t i = 0; i < NumExtraThreads; i++) {
                        os::WaitThread(g_extra_threads + i);
                    }
                }
            }

        }

    }

    // ========================================================================
    // Configuration IPC Service (ryu:cfg)
    // ========================================================================

    namespace cfg {

        /// Thread priority for config service
        const s32 ThreadPriority = 10;

        /// Thread stack size
        const size_t ThreadStackSize = 0x2000;

        /// Thread stack
        alignas(os::MemoryPageSize) u8 g_thread_stack[ThreadStackSize];
        os::ThreadType g_thread;

        /// Server manager options for config service
        struct ConfigServerManagerOptions {
            static constexpr size_t PointerBufferSize   = 0x100;
            static constexpr size_t MaxDomains          = 0;
            static constexpr size_t MaxDomainObjects    = 0;
            static constexpr bool   CanDeferInvokeRequest = false;
            static constexpr bool   CanManageMitmServers  = false;
        };

        /// Maximum concurrent sessions for config service
        constexpr size_t MaxSessions = 2;

        /// Server manager for ryu:cfg service
        using ConfigServerManager = sf::hipc::ServerManager<1, ConfigServerManagerOptions, MaxSessions>;
        ConfigServerManager g_config_server_manager;

        /// Config service thread entry point
        void LoopConfigServerThread(void*) {
            g_config_server_manager.LoopProcess();
        }

        /// Log maintenance thread stack
        alignas(os::MemoryPageSize) u8 g_log_thread_stack[0x1000];
        os::ThreadType g_log_thread;

        /// Log maintenance thread entry point (checks file idle timeout)
        void LoopLogMaintenanceThread(void*) {
            while (true) {
                // Sleep for 2 seconds
                svc::SleepThread(TimeSpan::FromSeconds(2).GetNanoSeconds());

                // Check if log file should be closed due to idle timeout
                ryu_ldn::debug::g_logger.check_idle_timeout();
            }
        }

    }

    // ========================================================================
    // System Module Initialization
    // ========================================================================


    // ========================================================================
    namespace init {

        void InitializeSystemModule() {
            // Initialize service manager connection
            R_ABORT_UNLESS(sm::Initialize());

            // Initialize filesystem
            fs::InitializeForSystem();
            fs::SetAllocator(mitm::Allocate, mitm::Deallocate);
            fs::SetEnabledAutoAbort(false);

            // Mount SD card for configuration
            R_ABORT_UNLESS(fs::MountSdCard("sdmc"));

            // Ensure config file exists (create with defaults if not)
            ryu_ldn::config::ensure_config_exists(ryu_ldn::config::CONFIG_PATH);

            // Load configuration
            ryu_ldn::config::Config config = ryu_ldn::config::get_default_config();
            ryu_ldn::config::load_config(ryu_ldn::config::CONFIG_PATH, config);

            // Initialize logger with debug settings
            ryu_ldn::debug::g_logger.init(config.debug, ryu_ldn::config::LOG_PATH);
            LOG_INFO("ryu_ldn_nx sysmodule starting");
            LOG_INFO("Config loaded from %s", ryu_ldn::config::CONFIG_PATH);

            // Load game whitelist from file (once at startup)
            ryu_ldn::config::LoadWhitelist();
            LOG_VERBOSE("Server: %s:%u", config.server.host, config.server.port);

            // Initialize network services
            R_ABORT_UNLESS(nifmInitialize(NifmServiceType_Admin));
            R_ABORT_UNLESS(bsdInitialize(&LibnxBsdInitConfig,
                                          LibnxSocketInitConfig.num_bsd_sessions,
                                          LibnxSocketInitConfig.bsd_service_type));
            R_ABORT_UNLESS(socketInitialize(&LibnxSocketInitConfig));

        }

        void FinalizeSystemModule() {
            LOG_INFO("ryu_ldn_nx sysmodule shutting down");

            // Flush logs first, then tear down in reverse init order:
            // socket → bsd → nifm. The socket layer must exit before BSD
            // because libnx socket cleanup closes file descriptors that the
            // BSD service still tracks.
            ryu_ldn::debug::g_logger.flush();
            socketExit();
            bsdExit();
            nifmExit();
            fs::Unmount("sdmc");
        }

        void Startup() {
            // Initialize the global malloc allocator
            init::InitializeAllocator(g_malloc_buffer, sizeof(g_malloc_buffer));
        }

    }

    // ========================================================================
    // Exit Handler (should never be called)
    // ========================================================================

    void NORETURN Exit(int rc) {
        AMS_UNUSED(rc);
        AMS_ABORT("Exit called by immortal process");
    }

    // ========================================================================
    // Main Entry Point
    // ========================================================================

    void Main() {
        // Initialize global configuration for IPC service
        ryu_ldn::ipc::InitializeConfig();

        // ====================================================================
        // Register ryu:cfg configuration service
        // ====================================================================
        LOG_INFO("Registering ryu:cfg config service");
        constexpr sm::ServiceName ConfigServiceName = sm::ServiceName::Encode("ryu:cfg");

        // Create the config service object and register it
        auto config_service = sf::CreateSharedObjectEmplaced<
            ryu_ldn::ipc::IConfigService,
            ryu_ldn::ipc::ConfigService>();

        R_ABORT_UNLESS(cfg::g_config_server_manager.RegisterObjectForServer(
            std::move(config_service), ConfigServiceName, cfg::MaxSessions));
        LOG_INFO("Config service ryu:cfg registered successfully");

        // Create config service thread
        R_ABORT_UNLESS(os::CreateThread(
            &cfg::g_thread,
            cfg::LoopConfigServerThread,
            nullptr,
            cfg::g_thread_stack,
            cfg::ThreadStackSize,
            cfg::ThreadPriority));

        os::SetThreadNamePointer(&cfg::g_thread, "ryu_ldn::CfgThread");
        os::StartThread(&cfg::g_thread);

        // Create log maintenance thread (for idle timeout)
        R_ABORT_UNLESS(os::CreateThread(
            &cfg::g_log_thread,
            cfg::LoopLogMaintenanceThread,
            nullptr,
            cfg::g_log_thread_stack,
            sizeof(cfg::g_log_thread_stack),
            cfg::ThreadPriority + 5));  // Lower priority than config service

        os::SetThreadNamePointer(&cfg::g_log_thread, "ryu_ldn::LogThread");
        os::StartThread(&cfg::g_log_thread);

        // ====================================================================
        // Register MITM services
        // ====================================================================

        // Register ldn:u MITM service (port 0)
        LOG_INFO("Registering ldn:u MITM service");
        constexpr sm::ServiceName LdnMitmServiceName = sm::ServiceName::Encode("ldn:u");
        R_ABORT_UNLESS((mitm::g_server_manager.RegisterMitmServer<
            mitm::ldn::LdnMitMService>(0, LdnMitmServiceName)));
        LOG_INFO("ldn:u MITM service registered successfully");

        // Register bsd:u MITM service (port 1)
        // This allows us to intercept game sockets that target LDN addresses (10.114.x.x)
        LOG_INFO("Registering bsd:u MITM service");
        constexpr sm::ServiceName BsdMitmServiceName = sm::ServiceName::Encode("bsd:u");
        R_ABORT_UNLESS((mitm::g_bsd_server_manager.RegisterMitmServer<
            mitm::bsd::BsdMitmService>(0, BsdMitmServiceName)));
        LOG_INFO("bsd:u MITM service registered successfully");

        // bsd:u server threads
        for (size_t i = 0; i < mitm::BsdThreadCount; i++) {
            R_ABORT_UNLESS(os::CreateThread(
                &mitm::g_bsd_threads[i],
                mitm::LoopBsdServerThread,
                nullptr,
                mitm::g_bsd_thread_stacks[i],
                mitm::BsdThreadStackSize,
                mitm::ThreadPriority));
            os::SetThreadNamePointer(&mitm::g_bsd_threads[i], "ryu_ldn::BsdThread");
            os::StartThread(&mitm::g_bsd_threads[i]);
        }



        // Create MITM processing thread
        R_ABORT_UNLESS(os::CreateThread(
            &mitm::g_thread,
            mitm::ProcessForServerOnAllThreads,
            nullptr,
            mitm::g_thread_stack,
            mitm::ThreadStackSize,
            mitm::ThreadPriority));

        os::SetThreadNamePointer(&mitm::g_thread, "ryu_ldn::MainThread");
        os::StartThread(&mitm::g_thread);

        // Wait for MITM thread (runs forever)
        // Note: Config thread also runs forever in parallel
        os::WaitThread(&mitm::g_thread);
    }

}

// ============================================================================
// Custom Memory Allocators
// ============================================================================

namespace {

    /// Throwing new must never return nullptr (GCC drops the null checks
    /// after it), and exceptions are off: abort with the cause instead of
    /// crashing later on a near-null write.
    void* AllocateOrAbort(size_t size) {
        void* p = ams::mitm::Allocate(size != 0 ? size : 1);
        AMS_ABORT_UNLESS(p != nullptr, "ryu_ldn heap exhausted (operator new, size=%zu)", size);
        return p;
    }

}

void* operator new(size_t size) {
    return AllocateOrAbort(size);
}

void* operator new(size_t size, const std::nothrow_t&) {
    return ams::mitm::Allocate(size);
}

void operator delete(void* p) {
    return ams::mitm::Deallocate(p, 0);
}

void operator delete(void* p, size_t size) {
    return ams::mitm::Deallocate(p, size);
}

void* operator new[](size_t size) {
    return AllocateOrAbort(size);
}

void* operator new[](size_t size, const std::nothrow_t&) {
    return ams::mitm::Allocate(size);
}

void operator delete[](void* p) {
    return ams::mitm::Deallocate(p, 0);
}

void operator delete[](void* p, size_t size) {
    return ams::mitm::Deallocate(p, size);
}
