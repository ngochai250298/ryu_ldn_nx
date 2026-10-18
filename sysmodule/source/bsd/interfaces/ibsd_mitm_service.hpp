/**
 * @file ibsd_mitm_service.hpp
 * @brief BSD MITM Service interface definition (bsd:u)
 *
 * This file defines the IPC interface for the BSD socket MITM service.
 * We intercept bsd:u to detect and proxy LDN traffic through the RyuLdn server.
 *
 * ## Strategy
 *
 * Unlike the LDN MITM which replaces the entire service, the BSD MITM:
 * 1. Forwards most calls to the real bsd:u service transparently
 * 2. Tracks sockets that bind/connect to LDN addresses (10.114.x.x)
 * 3. Proxies send/recv for tracked sockets via ProxyData packets
 *
 * ## IPC Format Notes
 *
 * IMPORTANT: nnSdk sends RegisterClient data as RAW INLINE data, not as buffers.
 * The input is a 48-byte struct: LibraryConfigData(32) + pid_placeholder(8) + tmem_size(8)
 * Reference: libnx bsd.c _bsdRegisterClient()
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#pragma once

#include <stratosphere.hpp>
#include "../bsd_types.hpp"

/**
 * @brief Interface definition for IBsdMitmService
 *
 * ## Reply layout
 *
 * Every bsd:u reply starts with `struct { int ret; int errno_; }`, followed
 * by any extra output (addrlen/optlen); errno_ is only read when ret < 0
 * (libnx bsd.c `_bsdDispatchImpl`). Out arguments of the same alignment are
 * laid out in declaration order, so each command declares `out_ret` first,
 * then `out_errno`, then any length.
 *
 * ## Request layout
 *
 * Buffer counts and types must match what the client sends exactly, or
 * Atmosphere rejects the request (`HipcCommandProcessor::PrepareForProcess`).
 * The declarations follow libnx bsd.c, which mirrors the SDK client.
 *
 * ## Commands not declared here
 *
 * Atmosphere forwards any command id missing from this interface to the real
 * service untouched (`ProcessMessageForMitmImpl`). These never carry LDN
 * traffic on a proxied socket, or cannot be parsed safely, so they pass through:
 * - 1 StartMonitoring, 4 Open, 7 Sysctl, 23 ShutdownAllSockets,
 *   27 DuplicateSocket, 28 GetResourceStatistics, 31 EventFd,
 *   32 RegisterResourceStatisticsName, 34 GetSocketStatistics, 35 NifIoctl,
 *   36-38, 40 ShutdownAllSockets: no per-socket data path.
 * - 39 NoSfEventFd and 41: write errors on NX (switchbrew Sockets services).
 * - 29 RecvMMsg, 30 SendMMsg, 42 SendMMsgNoMem, 43 RecvMMsgNoMem, 44:
 *   the batched message layout inside the buffer is undocumented (42-44 have
 *   no published request layout at all). A guessed declaration would make
 *   Atmosphere reject the command for every intercepted game, which is worse
 *   than pass-through. On a proxied fd they reach the real, unbound socket and
 *   fail or time out there; the LDN traffic is lost but nothing hangs in the
 *   proxy. Intercept them once a game is seen using them.
 */
#define AMS_RYU_BSD_MITM_SERVICE(C, H)                                                                                  \
    /* Cmd 0: RegisterClient. In: LibraryConfigData(32) + pid placeholder(8) + tmem_size(8), sorted by alignment.     */\
    /* Out: u64 (libnx treats it as the pid).                                                                          */\
    AMS_SF_METHOD_INFO(C, H, 0,   Result, RegisterClient,                                                               \
        (ams::sf::Out<u64> out_result,                                                                                  \
         const ryu_ldn::bsd::LibraryConfigData &config,                                                                 \
         const ams::sf::ClientProcessId &client_pid,                                                                    \
         u64 tmem_size,                                                                                                 \
         ams::sf::CopyHandle &&transfer_memory),                                                                        \
        (out_result, config, client_pid, tmem_size, std::move(transfer_memory)))                                       \
    AMS_SF_METHOD_INFO(C, H, 2,   Result, Socket,                                                                       \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol),                   \
        (out_ret, out_errno, domain, type, protocol))                                                                   \
    AMS_SF_METHOD_INFO(C, H, 3,   Result, SocketExempt,                                                                 \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol),                   \
        (out_ret, out_errno, domain, type, protocol))                                                                   \
    /* Cmd 5: Select. In: { int nfds; BsdSelectTimeval timeout; }, 3 in + 3 out fd_set buffers.                       */\
    AMS_SF_METHOD_INFO(C, H, 5,   Result, Select,                                                                       \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno,                                                        \
         s32 nfds, const ryu_ldn::bsd::SelectTimeval &timeout,                                                          \
         const ams::sf::InAutoSelectBuffer &readfds_in,                                                                 \
         const ams::sf::InAutoSelectBuffer &writefds_in,                                                                \
         const ams::sf::InAutoSelectBuffer &errorfds_in,                                                                \
         ams::sf::OutAutoSelectBuffer readfds_out,                                                                      \
         ams::sf::OutAutoSelectBuffer writefds_out,                                                                     \
         ams::sf::OutAutoSelectBuffer errorfds_out),                                                                    \
        (out_ret, out_errno, nfds, timeout, readfds_in, writefds_in, errorfds_in,                                       \
         readfds_out, writefds_out, errorfds_out))                                                                      \
    AMS_SF_METHOD_INFO(C, H, 6,   Result, Poll,                                                                         \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno,                                                        \
         const ams::sf::InAutoSelectBuffer &fds_in, ams::sf::OutAutoSelectBuffer fds_out,                               \
         s32 nfds, s32 timeout),                                                                                        \
        (out_ret, out_errno, fds_in, fds_out, nfds, timeout))                                                           \
    AMS_SF_METHOD_INFO(C, H, 8,   Result, Recv,                                                                         \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, s32 flags,                                     \
         ams::sf::OutAutoSelectBuffer buffer),                                                                          \
        (out_ret, out_errno, fd, flags, buffer))                                                                        \
    AMS_SF_METHOD_INFO(C, H, 9,   Result, RecvFrom,                                                                     \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addrlen,                         \
         s32 fd, s32 flags,                                                                                             \
         ams::sf::OutAutoSelectBuffer buffer,                                                                           \
         ams::sf::OutAutoSelectBuffer addr_out),                                                                        \
        (out_ret, out_errno, out_addrlen, fd, flags, buffer, addr_out))                                                 \
    AMS_SF_METHOD_INFO(C, H, 10,  Result, Send,                                                                         \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, s32 flags,                                     \
         const ams::sf::InAutoSelectBuffer &buffer),                                                                    \
        (out_ret, out_errno, fd, flags, buffer))                                                                        \
    AMS_SF_METHOD_INFO(C, H, 11,  Result, SendTo,                                                                       \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, s32 flags,                                     \
         const ams::sf::InAutoSelectBuffer &buffer,                                                                     \
         const ams::sf::InAutoSelectBuffer &addr),                                                                      \
        (out_ret, out_errno, fd, flags, buffer, addr))                                                                  \
    AMS_SF_METHOD_INFO(C, H, 12,  Result, Accept,                                                                       \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addrlen,                         \
         s32 fd, ams::sf::OutAutoSelectBuffer addr_out),                                                                \
        (out_ret, out_errno, out_addrlen, fd, addr_out))                                                                \
    AMS_SF_METHOD_INFO(C, H, 13,  Result, Bind,                                                                         \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd,                                                \
         const ams::sf::InAutoSelectBuffer &addr),                                                                      \
        (out_ret, out_errno, fd, addr))                                                                                 \
    AMS_SF_METHOD_INFO(C, H, 14,  Result, Connect,                                                                      \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd,                                                \
         const ams::sf::InAutoSelectBuffer &addr),                                                                      \
        (out_ret, out_errno, fd, addr))                                                                                 \
    AMS_SF_METHOD_INFO(C, H, 15,  Result, GetPeerName,                                                                  \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addrlen,                         \
         s32 fd, ams::sf::OutAutoSelectBuffer addr_out),                                                                \
        (out_ret, out_errno, out_addrlen, fd, addr_out))                                                                \
    AMS_SF_METHOD_INFO(C, H, 16,  Result, GetSockName,                                                                  \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addrlen,                         \
         s32 fd, ams::sf::OutAutoSelectBuffer addr_out),                                                                \
        (out_ret, out_errno, out_addrlen, fd, addr_out))                                                                \
    AMS_SF_METHOD_INFO(C, H, 17,  Result, GetSockOpt,                                                                   \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_optlen,                          \
         s32 fd, s32 level, s32 optname, ams::sf::OutAutoSelectBuffer optval),                                          \
        (out_ret, out_errno, out_optlen, fd, level, optname, optval))                                                   \
    AMS_SF_METHOD_INFO(C, H, 18,  Result, Listen,                                                                       \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, s32 backlog),                                  \
        (out_ret, out_errno, fd, backlog))                                                                              \
    /* Cmd 19: Ioctl. In: { int fd; int request; int bufcount; }, 4 in + 4 out buffers.                               */\
    AMS_SF_METHOD_INFO(C, H, 19,  Result, Ioctl,                                                                        \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, u32 request, u32 bufcount,                     \
         const ams::sf::InAutoSelectBuffer &in1, const ams::sf::InAutoSelectBuffer &in2,                                \
         const ams::sf::InAutoSelectBuffer &in3, const ams::sf::InAutoSelectBuffer &in4,                                \
         ams::sf::OutAutoSelectBuffer out1, ams::sf::OutAutoSelectBuffer out2,                                          \
         ams::sf::OutAutoSelectBuffer out3, ams::sf::OutAutoSelectBuffer out4),                                         \
        (out_ret, out_errno, fd, request, bufcount, in1, in2, in3, in4, out1, out2, out3, out4))                        \
    AMS_SF_METHOD_INFO(C, H, 20,  Result, Fcntl,                                                                        \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, s32 cmd, s32 arg),                             \
        (out_ret, out_errno, fd, cmd, arg))                                                                             \
    AMS_SF_METHOD_INFO(C, H, 21,  Result, SetSockOpt,                                                                   \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, s32 level, s32 optname,                        \
         const ams::sf::InAutoSelectBuffer &optval),                                                                    \
        (out_ret, out_errno, fd, level, optname, optval))                                                               \
    AMS_SF_METHOD_INFO(C, H, 22,  Result, Shutdown,                                                                     \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, s32 how),                                      \
        (out_ret, out_errno, fd, how))                                                                                  \
    AMS_SF_METHOD_INFO(C, H, 24,  Result, Write,                                                                        \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd,                                                \
         const ams::sf::InAutoSelectBuffer &buffer),                                                                    \
        (out_ret, out_errno, fd, buffer))                                                                               \
    AMS_SF_METHOD_INFO(C, H, 25,  Result, Read,                                                                         \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd,                                                \
         ams::sf::OutAutoSelectBuffer buffer),                                                                          \
        (out_ret, out_errno, fd, buffer))                                                                               \
    AMS_SF_METHOD_INFO(C, H, 26,  Result, Close,                                                                        \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd),                                               \
        (out_ret, out_errno, fd))                                                                                       \
    /* Cmd 33: RegisterClientShared [10.0.0+]. Same as RegisterClient without the transfer memory handle.             */\
    AMS_SF_METHOD_INFO(C, H, 33,  Result, RegisterClientShared,                                                         \
        (ams::sf::Out<u64> out_result,                                                                                  \
         const ryu_ldn::bsd::LibraryConfigData &config,                                                                 \
         const ams::sf::ClientProcessId &client_pid,                                                                    \
         u64 tmem_size),                                                                                                \
        (out_result, config, client_pid, tmem_size),                                                                    \
        hos::Version_10_0_0)

// Define the MITM interface with a unique ID
AMS_SF_DEFINE_MITM_INTERFACE(ams::mitm::bsd, IBsdMitmService, AMS_RYU_BSD_MITM_SERVICE, 0xB5D50C81)
